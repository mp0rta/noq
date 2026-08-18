//! Bundling of several pinned UDP sockets behind one [`AsyncUdpSocket`].
//!
//! Multipath QUIC distinguishes paths by their 4-tuple, and this endpoint
//! socket selects the member socket for each outgoing datagram by matching
//! [`Transmit::src_ip`] against the member's local IP. This lets an
//! application pin each path to a network interface (`SO_BINDTODEVICE` on
//! Linux) instead of relying on the routing table for source-address
//! selection on a single wildcard socket.

use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr, UdpSocket},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use udp::{RecvMeta, Transmit};

use crate::{AsyncUdpSocket, Runtime, UdpSender};

/// How one member socket is tied to an interface.
#[derive(Debug, Clone)]
pub enum SocketPin {
    /// Bind to the wildcard address and pin egress with `SO_BINDTODEVICE`.
    /// Requires `CAP_NET_RAW` (typically root). Linux/Android only.
    Iface(String),
    /// Bind to this specific local IP (ephemeral port). No special privileges.
    Ip(IpAddr),
}

/// Several per-interface UDP sockets behind a single [`AsyncUdpSocket`].
#[derive(Debug)]
pub struct MultiSocket {
    inner: Vec<Box<dyn AsyncUdpSocket>>,
    /// The local IP each member sends from; the dispatch key for transmits.
    locals: Vec<Option<IpAddr>>,
}

impl MultiSocket {
    /// Binds one member socket per spec. `specs[0]` is the primary socket:
    /// transmits without a source IP (e.g. the handshake) leave through it.
    ///
    /// Each spec pairs the pin with the local IP this member represents.
    /// For [`SocketPin::Ip`] the IP may be omitted (it is implied); for
    /// [`SocketPin::Iface`] the caller resolves the interface's address
    /// (the socket itself stays wildcard-bound).
    pub fn bind(
        specs: &[(SocketPin, Option<IpAddr>)],
        runtime: &Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        if specs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MultiSocket needs at least one socket spec",
            ));
        }
        let mut inner = Vec::with_capacity(specs.len());
        let mut locals = Vec::with_capacity(specs.len());
        for (pin, local) in specs {
            let socket = match pin {
                SocketPin::Iface(name) => bind_to_device(name)?,
                SocketPin::Ip(ip) => UdpSocket::bind((*ip, 0))?,
            };
            inner.push(runtime.wrap_udp_socket(socket)?);
            locals.push(match (pin, local) {
                (SocketPin::Ip(ip), None) => Some(*ip),
                (_, local) => *local,
            });
        }
        Ok(Self { inner, locals })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_to_device(name: &str) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
    socket2::SockRef::from(&socket).bind_device(Some(name.as_bytes()))?;
    Ok(socket)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bind_to_device(_name: &str) -> io::Result<UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SocketPin::Iface requires SO_BINDTODEVICE (Linux/Android only)",
    ))
}

/// Picks the member socket for a transmit: an exact source-IP match wins;
/// no source IP or no match falls back to the primary (index 0).
fn pick_socket(src_ip: Option<IpAddr>, locals: &[Option<IpAddr>]) -> usize {
    if let Some(src) = src_ip {
        if let Some(i) = locals.iter().position(|l| *l == Some(src)) {
            return i;
        }
    }
    0
}

impl AsyncUdpSocket for MultiSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(MultiSender {
            senders: self.inner.iter().map(|s| s.create_sender()).collect(),
            locals: self.locals.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Polls members in order and returns the first Ready result. Every
        // Pending member has registered the waker, so no wakeup is lost.
        // Member 0 is always tried first; under sustained load on the
        // primary this can delay the others' receive path (iroh's
        // multiplexer rotates the start index) — acceptable for now.
        for socket in &mut self.inner {
            if let Poll::Ready(res) = socket.poll_recv(cx, bufs, meta) {
                return Poll::Ready(res);
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner[0].local_addr()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.inner
            .iter()
            .map(|s| s.max_receive_segments())
            .min()
            .unwrap_or(NonZeroUsize::MIN)
    }

    fn may_fragment(&self) -> bool {
        self.inner.iter().any(|s| s.may_fragment())
    }
}

#[derive(Debug)]
struct MultiSender {
    senders: Vec<Pin<Box<dyn UdpSender>>>,
    locals: Vec<Option<IpAddr>>,
}

impl UdpSender for MultiSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let idx = pick_socket(transmit.src_ip, &this.locals);
        match this.senders[idx].as_mut().poll_send(transmit, cx) {
            // A member's send failure must not reach the connection driver:
            // the driver terminates the whole connection on a send error,
            // but with multipath a downed interface (ENETDOWN/ENODEV) is
            // exactly the condition the surviving paths should ride out.
            // Drop the datagram and let loss recovery / path failover
            // handle it.
            Poll::Ready(Err(e)) => {
                tracing::warn!("multisocket: send on socket {idx} failed: {e} (datagram dropped)");
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.senders
            .iter()
            .map(|s| s.max_transmit_segments())
            .min()
            .unwrap_or(NonZeroUsize::MIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn src_match_selects_socket() {
        let locals = [
            Some("10.10.0.1".parse().unwrap()),
            Some("10.20.0.1".parse().unwrap()),
        ];
        assert_eq!(pick_socket(Some("10.20.0.1".parse().unwrap()), &locals), 1);
    }

    #[test]
    fn none_falls_back_to_primary() {
        let locals = [
            Some("10.10.0.1".parse().unwrap()),
            Some("10.20.0.1".parse().unwrap()),
        ];
        assert_eq!(pick_socket(None, &locals), 0);
    }

    #[test]
    fn unmatched_falls_back_to_primary() {
        let locals = [Some("10.10.0.1".parse().unwrap())];
        assert_eq!(
            pick_socket(Some("192.168.1.1".parse().unwrap()), &locals),
            0
        );
    }
}
