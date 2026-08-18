//! Two-path multipath demo over real UDP sockets.
//!
//! server: cargo run --example multipath --features multisocket -- server 0.0.0.0:4433
//! client (single wildcard socket, per-packet source selection):
//!     cargo run --example multipath --features multisocket -- client <server_addr> \
//!         --local-ip <ip_a> --local-ip <ip_b> [--remote2 <addr>] [--hold <secs>]
//! client (one socket per NIC via MultiSocket + SO_BINDTODEVICE, needs root):
//!     cargo run --example multipath --features multisocket -- client <server_addr> \
//!         --ifaces <nic_a>,<nic_b> [--remote2 <addr>] [--hold <secs>]
//!
//! The client connects via the first socket/default route (primary path),
//! then opens a second path from the last --local-ip (or the last --ifaces
//! member's address) to --remote2 if given, else the same server addr.
//! Both sides print path events.
//!
//! Note: in --local-ip mode the first --local-ip is informational only. The
//! primary path's local address is chosen by kernel routing (the socket is
//! wildcard-bound); do not try to bind it.

use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    pin::pin,
    sync::Arc,
    time::Duration,
};

use noq::{
    ClientConfig, Connection, Endpoint, EndpointConfig, FourTuple, MultiSocket, PathError,
    PathStatus, ServerConfig, SocketPin, TransportConfig,
};
use proto::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio_stream::StreamExt;

type DynError = Box<dyn Error + Send + Sync + 'static>;

const USAGE: &str = "usage: multipath server <bind_addr>\n       multipath client <server_addr> --local-ip <ip> [--local-ip <ip>] [--remote2 <addr>] [--hold <secs>]\n       multipath client <server_addr> --ifaces <nic_a>,<nic_b> [--remote2 <addr>] [--hold <secs>]";

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") => {
            let addr = args.get(1).ok_or(USAGE)?.parse()?;
            run_server(addr).await
        }
        Some("client") => {
            let server_addr: SocketAddr = args.get(1).ok_or(USAGE)?.parse()?;
            let mut local_ips: Vec<IpAddr> = Vec::new();
            let mut ifaces: Vec<String> = Vec::new();
            let mut remote2: Option<SocketAddr> = None;
            let mut hold_secs = 60u64;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--local-ip" => {
                        local_ips.push(args.get(i + 1).ok_or(USAGE)?.parse()?);
                        i += 2;
                    }
                    "--ifaces" => {
                        ifaces = args
                            .get(i + 1)
                            .ok_or(USAGE)?
                            .split(',')
                            .map(str::to_string)
                            .collect();
                        i += 2;
                    }
                    "--remote2" => {
                        remote2 = Some(args.get(i + 1).ok_or(USAGE)?.parse()?);
                        i += 2;
                    }
                    "--hold" => {
                        hold_secs = args.get(i + 1).ok_or(USAGE)?.parse()?;
                        i += 2;
                    }
                    other => return Err(format!("unknown arg {other}\n{USAGE}").into()),
                }
            }
            run_client(server_addr, local_ips, ifaces, remote2, hold_secs).await
        }
        _ => Err(USAGE.into()),
    }
}

/// Multipath-enabled transport config shared by both sides. Multipath is
/// negotiated only if BOTH sides set max_concurrent_multipath_paths.
/// Short per-path keep-alive/idle-timeout make path failure detectable
/// within a few seconds for the failover experiment.
fn transport_config() -> TransportConfig {
    let mut tc = TransportConfig::default();
    tc.max_concurrent_multipath_paths(3);
    tc.default_path_keep_alive_interval(Some(Duration::from_secs(1)));
    tc.default_path_max_idle_timeout(Some(Duration::from_secs(3)));
    tc
}

fn spawn_event_printer(side: &'static str, conn: Connection) {
    let events = conn.path_events();
    let id = conn.stable_id();
    tokio::spawn(async move {
        let mut events = pin!(events);
        while let Some(ev) = events.next().await {
            println!("[{side}] conn={id} path_event={ev:?}");
        }
    });
}

async fn run_server(addr: SocketAddr) -> Result<(), DynError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut server_config = ServerConfig::with_single_cert(vec![cert_der], priv_key.into())?;
    server_config.transport_config(Arc::new(transport_config()));

    let endpoint = Endpoint::server(server_config, addr)?;
    println!("[server] listening on {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                println!("[server] accept failed: {e}");
                continue;
            }
        };
        println!(
            "[server] connection accepted: conn={} multipath={}",
            conn.stable_id(),
            conn.is_multipath_enabled()
        );
        spawn_event_printer("server", conn.clone());
        tokio::spawn(echo_loop(conn));
    }
    Ok(())
}

async fn echo_loop(conn: Connection) {
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let data = match recv.read_to_end(64 * 1024).await {
                    Ok(data) => data,
                    Err(e) => {
                        println!("[server] read failed: {e}");
                        continue;
                    }
                };
                if let Err(e) = send.write_all(&data).await {
                    println!("[server] write failed: {e}");
                    continue;
                }
                let _ = send.finish();
            }
            Err(e) => {
                println!("[server] connection ended: {e}");
                break;
            }
        }
    }
}

async fn run_client(
    server_addr: SocketAddr,
    local_ips: Vec<IpAddr>,
    ifaces: Vec<String>,
    remote2: Option<SocketAddr>,
    hold_secs: u64,
) -> Result<(), DynError> {
    let (endpoint, second_local) = if ifaces.is_empty() {
        // Wildcard bind: per-path source IPs are selected per packet (IP_PKTINFO).
        let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        let second_local = *local_ips.last().ok_or("need --local-ip or --ifaces")?;
        (endpoint, second_local)
    } else {
        // One socket per NIC, pinned with SO_BINDTODEVICE, bundled by MultiSocket.
        let mut specs = Vec::new();
        let mut resolved = Vec::new();
        for name in &ifaces {
            let ip = resolve_iface_ipv4(name)?;
            println!("[client] iface {name} -> {ip}");
            specs.push((SocketPin::Iface(name.clone()), Some(ip)));
            resolved.push(ip);
        }
        let runtime = noq::default_runtime().ok_or("no async runtime found")?;
        let multisocket = MultiSocket::bind(&specs, &runtime)?;
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            Box::new(multisocket),
            runtime,
        )?;
        let second_local = *resolved.last().ok_or("need at least one iface")?;
        (endpoint, second_local)
    };
    let mut client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth(),
    )?));
    client_config.transport_config(Arc::new(transport_config()));
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(server_addr, "localhost")?.await?;
    println!(
        "[client] connected: conn={} multipath={}",
        conn.stable_id(),
        conn.is_multipath_enabled()
    );
    if !conn.is_multipath_enabled() {
        return Err("multipath was not negotiated".into());
    }
    spawn_event_printer("client", conn.clone());

    echo_once(&conn, b"hello over the primary path").await?;
    println!("[client] primary path echo OK");

    let second_remote = remote2.unwrap_or(server_addr);
    let tuple = FourTuple::new(second_remote, Some(second_local));
    // Right after the handshake the peer may not have issued enough CIDs for
    // a new path yet; retry the transient error (same as noq's own tests).
    let mut attempts = 0u32;
    let path = loop {
        match conn.open_path(tuple, PathStatus::Available).await {
            Ok(path) => break path,
            Err(PathError::RemoteCidsExhausted) if attempts < 50 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(format!("open_path failed: {e}").into()),
        }
    };
    println!(
        "second path established: id={:?} 4tuple={:?}",
        path.id(),
        path.network_path()
    );

    // Hold the connection and keep echoing so a path can be failed externally
    // (e.g. `ip link set <iface> down`) while traffic is flowing.
    for i in 0..hold_secs {
        tokio::time::sleep(Duration::from_secs(1)).await;
        match echo_once(&conn, format!("tick {i}").as_bytes()).await {
            Ok(()) => println!("[client] echo {i} OK"),
            Err(e) => println!("[client] echo {i} failed: {e}"),
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

fn resolve_iface_ipv4(name: &str) -> Result<IpAddr, DynError> {
    for iface in if_addrs::get_if_addrs()? {
        if iface.name == name {
            if let ip @ IpAddr::V4(_) = iface.ip() {
                return Ok(ip);
            }
        }
    }
    Err(format!("interface '{name}' has no IPv4 address").into())
}

async fn echo_once(conn: &Connection, msg: &[u8]) -> Result<(), DynError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(msg).await?;
    send.finish()?;
    let resp = recv.read_to_end(64 * 1024).await?;
    if resp != msg {
        return Err("echo mismatch".into());
    }
    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
