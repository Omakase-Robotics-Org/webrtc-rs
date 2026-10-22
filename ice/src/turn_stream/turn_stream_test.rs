use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use turn::auth::AuthHandler;
use util::Conn;

use super::*;
use crate::agent::agent_config::AgentConfig;
use crate::agent::agent_vnet_test::{connect_with_vnet, on_connected};
use crate::agent::Agent;
use crate::candidate::CandidateType;
use crate::error::Error;
use crate::network_type::supported_network_types;

/// Roots the TLS client trusts in tests besides webpki's (the self-signed
/// certificate of the localhost TURN/TLS server).
static EXTRA_ROOTS: std::sync::Mutex<Vec<CertificateDer<'static>>> =
    std::sync::Mutex::new(Vec::new());

pub(super) fn extra_roots() -> Vec<CertificateDer<'static>> {
    EXTRA_ROOTS.lock().map(|r| r.clone()).unwrap_or_default()
}

/// A STUN binding request with a body of `body` bytes (a multiple of 4).
fn stun(body: usize, tag: u8) -> Vec<u8> {
    let mut m = vec![0x00, 0x01];
    m.extend_from_slice(&(body as u16).to_be_bytes());
    m.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    m.extend_from_slice(&[tag; 12]);
    m.extend(std::iter::repeat_n(tag, body));
    m
}

/// A ChannelData message on channel 0x4000 with `len` bytes of data,
/// padded (`pad`) or not.
fn channel_data(len: usize, tag: u8, pad: bool) -> Vec<u8> {
    let mut m = vec![0x40, 0x00];
    m.extend_from_slice(&(len as u16).to_be_bytes());
    m.extend(std::iter::repeat_n(tag, len));
    if pad {
        m.resize((m.len() + 3) & !3, 0);
    }
    m
}

#[test]
fn test_frame_split_across_reads() {
    let msg = stun(8, 7);
    let mut s = FrameSplitter::new();
    for (i, b) in msg.iter().enumerate() {
        assert_eq!(s.next_frame().unwrap(), None, "complete after {i} bytes");
        s.push(&[*b]);
    }
    assert_eq!(s.next_frame().unwrap(), Some(msg));
    assert_eq!(s.pending(), 0);
}

#[test]
fn test_two_frames_in_one_read() {
    let a = stun(4, 1);
    let b = channel_data(8, 2, true);
    let c = stun(0, 3);
    let mut bytes = a.clone();
    bytes.extend_from_slice(&b);
    bytes.extend_from_slice(&c[..10]);

    let mut s = FrameSplitter::new();
    s.push(&bytes);
    assert_eq!(s.next_frame().unwrap(), Some(a));
    assert_eq!(s.next_frame().unwrap(), Some(b));
    assert_eq!(s.next_frame().unwrap(), None);
    s.push(&c[10..]);
    assert_eq!(s.next_frame().unwrap(), Some(c));
}

#[test]
fn test_channel_data_padding() {
    // 5 bytes of data: a 4-byte header, the data and 3 bytes of padding on
    // the stream; the frame after it starts after the padding.
    let cd = channel_data(5, 9, true);
    assert_eq!(cd.len(), 12);
    assert_eq!(frame_len(&cd).unwrap(), Some(12));
    let next = stun(0, 4);
    let mut s = FrameSplitter::new();
    s.push(&cd);
    s.push(&next);
    let frame = s.next_frame().unwrap().unwrap();
    assert_eq!(frame, cd);
    let mut decoded = turn::proto::chandata::ChannelData {
        raw: frame,
        ..Default::default()
    };
    decoded.decode().unwrap();
    assert_eq!(decoded.data, vec![9; 5]);
    assert_eq!(s.next_frame().unwrap(), Some(next));

    // Outbound: an unpadded ChannelData is padded, a padded one and a STUN
    // message are written as they are.
    assert_eq!(outbound_frame(&channel_data(5, 9, false)), cd);
    assert_eq!(outbound_frame(&cd), cd);
    assert_eq!(outbound_frame(&stun(4, 1)), stun(4, 1));
}

#[test]
fn test_invalid_first_byte() {
    let mut s = FrameSplitter::new();
    s.push(&[0x80, 0, 0, 0]);
    assert!(s.next_frame().is_err());
    assert!(frame_len(&[0xc0, 0, 0, 0]).is_err());
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn test_conn_datagrams_over_a_stream() -> Result<(), util::Error> {
    let (near, mut far) = tokio::io::duplex(1024);
    let conn = TurnStreamConn::new(near, addr(1), addr(2));

    // Outbound: one datagram, one frame; an unpadded ChannelData is padded.
    conn.send_to(&stun(4, 1), addr(9)).await?;
    conn.send(&channel_data(3, 2, false)).await?;
    let mut got = vec![0u8; 24 + 8];
    far.read_exact(&mut got).await?;
    assert_eq!(&got[..24], &stun(4, 1)[..]);
    assert_eq!(&got[24..], &channel_data(3, 2, true)[..]);

    // Inbound: frames written in pieces arrive whole, one per recv, from the
    // stream's peer.
    let mut bytes = channel_data(6, 3, true);
    bytes.extend_from_slice(&stun(8, 4));
    far.write_all(&bytes[..5]).await?;
    far.flush().await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    far.write_all(&bytes[5..]).await?;
    let mut buf = vec![0u8; 1500];
    let (n, from) = conn.recv_from(&mut buf).await?;
    assert_eq!((&buf[..n], from), (&channel_data(6, 3, true)[..], addr(2)));
    let n = conn.recv(&mut buf).await?;
    assert_eq!(&buf[..n], &stun(8, 4)[..]);

    // Close: the peer reads the end of the stream, the conn refuses sends.
    conn.close().await?;
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), far.read_to_end(&mut rest))
        .await
        .expect("the stream is shut down on close")?;
    assert!(rest.is_empty());
    assert!(conn.send(&stun(0, 1)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn test_conn_peer_close_ends_recv() -> Result<(), util::Error> {
    let (near, far) = tokio::io::duplex(1024);
    let conn = TurnStreamConn::new(near, addr(1), addr(2));
    drop(far);
    let mut buf = vec![0u8; 64];
    assert!(conn.recv_from(&mut buf).await.is_err());
    Ok(())
}

struct TestAuthHandler;

impl AuthHandler for TestAuthHandler {
    fn auth_handle(
        &self,
        _username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> std::result::Result<Vec<u8>, turn::Error> {
        Ok(turn::auth::generate_auth_key(
            "username",
            "webrtc.rs",
            "password",
        ))
    }
}

/// A TURN server on `127.0.0.1` behind a TCP listener (with TLS when
/// `tls` is given): one `turn` server per accepted connection, its
/// `ConnConfig.conn` the accepted stream wrapped in [`TurnStreamConn`] — the
/// server's API takes its conns at construction, so a connection-oriented
/// listener is served one server per connection. Relayed addresses are UDP
/// on `127.0.0.1`. Each connection is proxied to the server's conn through
/// an in-memory pipe, so the end of a client's stream is observable: the
/// proxy returns when the client has shut its stream down. Returns the port,
/// the clients' addresses as accepted, and how many of them have ended.
async fn spawn_turn_stream_server(
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> std::io::Result<TestServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let accepted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ended = Arc::new(AtomicUsize::new(0));
    let (accepted2, ended2) = (Arc::clone(&accepted), Arc::clone(&ended));
    let task = tokio::spawn(async move {
        let mut servers = Vec::new();
        while let Ok((tcp, peer)) = listener.accept().await {
            accepted2.lock().unwrap().push(peer);
            let local = tcp.local_addr().unwrap();
            tcp.set_nodelay(true).unwrap();
            let (inner, outer) = tokio::io::duplex(64 * 1024);
            let ended3 = Arc::clone(&ended2);
            match &tls {
                None => {
                    tokio::spawn(proxy(tcp, outer, ended3));
                }
                Some(acceptor) => match acceptor.accept(tcp).await {
                    Ok(stream) => {
                        tokio::spawn(proxy(stream, outer, ended3));
                    }
                    Err(err) => {
                        log::warn!("test TURN/TLS server: handshake with {peer}: {err}");
                        continue;
                    }
                },
            }
            let conn: Arc<dyn Conn + Send + Sync> =
                Arc::new(TurnStreamConn::new(inner, local, peer));
            let server = turn::server::Server::new(turn::server::config::ServerConfig {
                realm: "webrtc.rs".to_owned(),
                auth_handler: Arc::new(TestAuthHandler),
                conn_configs: vec![turn::server::config::ConnConfig {
                    conn,
                    relay_addr_generator: Box::new(
                        turn::relay::relay_none::RelayAddressGeneratorNone {
                            address: "127.0.0.1".to_owned(),
                            net: Arc::new(util::vnet::net::Net::new(None)),
                        },
                    ),
                }],
                channel_bind_timeout: Duration::from_secs(0),
                alloc_close_notify: None,
            })
            .await
            .unwrap();
            servers.push(server);
        }
    });
    Ok(TestServer {
        port,
        accepted,
        ended,
        task,
    })
}

struct TestServer {
    port: u16,
    accepted: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    ended: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

/// Copies between a client's stream and the server's end of the pipe until
/// both directions have ended, then counts the connection as ended.
async fn proxy<S>(mut client: S, mut server: tokio::io::DuplexStream, ended: Arc<AtomicUsize>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    ended.fetch_add(1, Ordering::SeqCst);
}

/// Two relay-only agents whose one ICE server is `scheme:127.0.0.1:port`
/// with `transport=tcp` gather a relay candidate each over the stream,
/// connect through the server and exchange data both ways.
async fn relay_only_over_stream(
    scheme: SchemeType,
    host: &str,
    server: &TestServer,
) -> Result<(), Error> {
    let port = server.port;
    let url = Url {
        scheme,
        host: host.to_owned(),
        username: "username".to_owned(),
        password: "password".to_owned(),
        port,
        proto: ProtoType::Tcp,
    };
    let config = || AgentConfig {
        network_types: supported_network_types(),
        urls: vec![url.clone()],
        candidate_types: vec![CandidateType::Relay],
        ..Default::default()
    };

    let started = Instant::now();
    let a_agent = Arc::new(Agent::new(config()).await?);
    let (a_notifier, mut a_connected) = on_connected();
    a_agent.on_connection_state_change(a_notifier);
    let b_agent = Arc::new(Agent::new(config()).await?);
    let (b_notifier, mut b_connected) = on_connected();
    b_agent.on_connection_state_change(b_notifier);

    let (a_conn, b_conn) = tokio::time::timeout(
        Duration::from_secs(10),
        connect_with_vnet(&a_agent, &b_agent),
    )
    .await
    .map_err(|_| Error::Other("no connection within 10 s".to_owned()))??;
    let _ = a_connected.recv().await;
    let _ = b_connected.recv().await;

    // Each agent's one candidate is a relay candidate whose related address
    // is its end of a TCP connection the server accepted.
    let accepted = server.accepted.lock().unwrap().clone();
    assert_eq!(accepted.len(), 2, "one stream per agent");
    for agent in [&a_agent, &b_agent] {
        let candidates = agent.get_local_candidates().await?;
        assert_eq!(candidates.len(), 1, "one relay candidate");
        let c = &candidates[0];
        assert_eq!(c.candidate_type(), CandidateType::Relay);
        assert_eq!(c.address(), "127.0.0.1");
        let related = c.related_address().expect("a related address");
        let related = SocketAddr::new(related.address.parse().unwrap(), related.port);
        assert!(
            accepted.contains(&related),
            "related address {related} is a stream the server accepted ({accepted:?})"
        );
    }

    // Data both ways through the relays (ChannelData / Send indications
    // over both streams).
    let mut buf = vec![0u8; 1500];
    for i in 0..5u8 {
        a_conn.send(&[i; 100]).await?;
        let n = tokio::time::timeout(Duration::from_secs(2), b_conn.recv(&mut buf))
            .await
            .map_err(|_| Error::Other("a -> b lost".to_owned()))??;
        assert_eq!(&buf[..n], &[i; 100][..]);
        b_conn.send(&[i; 1200]).await?;
        let n = tokio::time::timeout(Duration::from_secs(2), a_conn.recv(&mut buf))
            .await
            .map_err(|_| Error::Other("b -> a lost".to_owned()))??;
        assert_eq!(&buf[..n], &[i; 1200][..]);
    }
    let elapsed = started.elapsed();
    log::info!("relay-only over {scheme} connected and exchanged in {elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");

    // Closing the agents closes their relay candidates and turn clients;
    // the streams go with them (the server's proxies see both directions
    // end).
    a_agent.close().await?;
    b_agent.close().await?;
    drop((a_conn, b_conn));
    let deadline = Instant::now() + Duration::from_secs(3);
    while server.ended.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < deadline,
            "streams still open 3 s after close: {} of 2 ended",
            server.ended.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

#[tokio::test]
async fn test_relay_only_connection_over_turn_tcp() -> Result<(), Error> {
    let server = spawn_turn_stream_server(None).await?;
    relay_only_over_stream(SchemeType::Turn, "127.0.0.1", &server).await?;
    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn test_relay_only_connection_over_turn_tls() -> Result<(), Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| Error::Other(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    EXTRA_ROOTS.lock().unwrap().push(cert_der.clone());
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Other(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .map_err(|e| Error::Other(e.to_string()))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let server = spawn_turn_stream_server(Some(acceptor)).await?;
    // The certificate names `localhost`: the client checks it against the
    // URL's host. `localhost` resolves IPv4 first (dial's order), where the
    // server listens.
    relay_only_over_stream(SchemeType::Turns, "localhost", &server).await?;
    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn test_tls_rejects_an_untrusted_certificate() -> Result<(), Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["untrusted.invalid".to_owned()])
        .map_err(|e| Error::Other(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Other(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .map_err(|e| Error::Other(e.to_string()))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let server = spawn_turn_stream_server(Some(acceptor)).await?;
    let port = server.port;

    let url = Url {
        scheme: SchemeType::Turns,
        host: "localhost".to_owned(),
        username: "username".to_owned(),
        password: "password".to_owned(),
        port,
        proto: ProtoType::Tcp,
    };
    let err = dial(&url, Duration::from_secs(2))
        .await
        .err()
        .expect("an untrusted certificate is refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn test_dial_deadline() -> Result<(), Error> {
    // A listener that never accepts still completes TCP's handshake
    // (backlog), so use TLS, whose handshake it never answers.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let url = Url {
        scheme: SchemeType::Turns,
        host: "127.0.0.1".to_owned(),
        username: "username".to_owned(),
        password: "password".to_owned(),
        port,
        proto: ProtoType::Tcp,
    };
    let started = Instant::now();
    let err = dial(&url, Duration::from_millis(300))
        .await
        .err()
        .expect("no handshake, no conn");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(listener);
    Ok(())
}
