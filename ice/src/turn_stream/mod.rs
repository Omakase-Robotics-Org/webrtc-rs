//! TURN over a byte stream: TCP (`turn:…?transport=tcp`) and TLS
//! (`turns:…?transport=tcp`).
//!
//! The `turn` client and server exchange datagrams through a [`Conn`]: every
//! STUN message, Send/Data indication and ChannelData message is one
//! `send_to` and one `recv_from`. Over TCP and TLS the same messages travel
//! back to back on one stream (RFC 5766 sec 2.1 and sec 11.5):
//!
//! - a STUN message is its 20-byte header plus the length in bytes 2-3
//!   (always a multiple of 4);
//! - a ChannelData message (first two bits `01`) is its 4-byte header plus the
//!   length in bytes 2-3, padded to a multiple of 4 — on a stream the padding
//!   is mandatory (RFC 5766 sec 11.5).
//!
//! [`TurnStreamConn`] is the [`Conn`] that does this framing over any
//! `AsyncRead + AsyncWrite` stream: a reader task splits the inbound bytes
//! into frames ([`FrameSplitter`]) and hands each to `recv`/`recv_from` as one
//! datagram from the stream's peer; a writer task writes each outbound
//! datagram as one frame. The target address of `send_to` is ignored: the
//! stream has one peer, the TURN server (or, on a server, the client).
//!
//! Sends keep datagram semantics: they are queued for the writer task and
//! never wait for the stream. When the stream cannot take more (its send
//! buffer and the queue are full, as on a stalled path), a datagram is
//! dropped, as a UDP socket would lose it, so a sender above (the ICE agent's
//! checks through the relay conn) is never held by a stalled TCP connection.
//!
//! [`dial`] opens the stream for a TURN URL (TCP, or TLS with the webpki
//! roots), bounded by one deadline for connect and handshake.
//!
//! # Pinned server certificates
//!
//! A `turns:` server is verified against the webpki roots (the Mozilla root
//! store), and its certificate must name the URL's host in a subjectAltName.
//! A private deployment whose TURN server carries a self-signed certificate,
//! or one issued by the deployment's own CA, is refused by that — correctly.
//! For such a server the caller pins the server's certificate: a pinned
//! certificate is the server's identity, so a server presenting exactly that
//! certificate (DER, byte for byte) is accepted without a name, chain or
//! validity check, and any other certificate is verified against the webpki
//! roots as without pins. The handshake signature is verified in either case,
//! so the server must hold the pinned certificate's private key.
//!
//! Pins reach a dial two ways, and both apply:
//!
//! - per agent, [`AgentConfig::turn_pinned_server_certs`](crate::agent::agent_config::AgentConfig::turn_pinned_server_certs);
//! - process-wide, [`pin_server_certs`], for callers that do not build the
//!   `AgentConfig` themselves (webrtc's `RTCPeerConnection` builds it from its
//!   `SettingEngine`, which has no field for this).
//!
//! No pins (the default) means the webpki roots alone: the verification of
//! stock rustls.

#[cfg(test)]
mod turn_stream_test;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};
use util::Conn;

/// A certificate in DER, as [`pin_server_certs`] and
/// `AgentConfig::turn_pinned_server_certs` take it (rustls' type).
pub use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::url::{ProtoType, SchemeType, Url};

/// A STUN message's fixed header.
const STUN_HEADER_SIZE: usize = 20;

/// A ChannelData message's header (channel number, length).
const CHANNEL_DATA_HEADER_SIZE: usize = 4;

/// Inbound frames buffered between the reader task and `recv_from`. When
/// they are not taken, the reader stops reading and TCP's flow control holds
/// the peer.
const INBOUND_FRAMES: usize = 64;

/// Outbound datagrams queued for the writer task. A datagram sent while the
/// queue is full is dropped (see the module documentation).
const OUTBOUND_FRAMES: usize = 64;

/// How long a closed conn's writer task may take to flush the queued frames
/// and shut the stream down (a TLS close_notify, a TCP FIN) before it is
/// aborted.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// How a frame starting with `header` is delimited on a stream.
///
/// Returns the frame's full length (header, body and padding) once the 4
/// bytes that carry it are present, `Ok(None)` before that, and an error
/// for a first byte that starts neither a STUN nor a ChannelData message:
/// a stream cannot be resynchronised after one.
pub fn frame_len(header: &[u8]) -> io::Result<Option<usize>> {
    if header.len() < 4 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    match header[0] >> 6 {
        0b00 => Ok(Some(STUN_HEADER_SIZE + len)),
        0b01 => Ok(Some(CHANNEL_DATA_HEADER_SIZE + padded(len))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TURN stream: first byte {:#04x} starts neither a STUN nor a ChannelData message",
                header[0]
            ),
        )),
    }
}

/// `len` rounded up to a multiple of 4.
fn padded(len: usize) -> usize {
    (len + 3) & !3
}

/// Splits the bytes read from a TURN stream into whole frames, however the
/// reads cut them.
#[derive(Debug, Default)]
pub struct FrameSplitter {
    buf: Vec<u8>,
}

impl FrameSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes as they were read.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole frame, `Ok(None)` while it is incomplete.
    pub fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        match frame_len(&self.buf)? {
            Some(len) if self.buf.len() >= len => Ok(Some(self.buf.drain(..len).collect())),
            _ => Ok(None),
        }
    }

    /// Bytes held that do not yet form a frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// One outbound datagram as a stream frame: a ChannelData message is padded
/// to a multiple of 4 if its sender did not (`turn`'s `ChannelData::encode`
/// does); anything else is written as it is.
pub fn outbound_frame(datagram: &[u8]) -> Vec<u8> {
    let mut frame = datagram.to_vec();
    if datagram.len() >= CHANNEL_DATA_HEADER_SIZE && datagram[0] >> 6 == 0b01 {
        frame.resize(padded(datagram.len()), 0);
    }
    frame
}

/// A [`Conn`] over a byte stream carrying TURN's framing (see the module
/// documentation). Closing it, or dropping it, ends both tasks and shuts the
/// stream down.
pub struct TurnStreamConn {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound: std::sync::Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    reader: JoinHandle<()>,
    writer: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl TurnStreamConn {
    /// Wraps `stream`, whose ends are `local_addr` and `remote_addr`, and
    /// starts its reader and writer tasks (on the current tokio runtime).
    pub fn new<S>(stream: S, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(INBOUND_FRAMES);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_FRAMES);

        let reader = tokio::spawn(async move {
            let mut splitter = FrameSplitter::new();
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let n = match rd.read(&mut chunk).await {
                    Ok(0) => {
                        log::debug!("TURN stream {remote_addr}: closed by the peer");
                        return;
                    }
                    Ok(n) => n,
                    Err(err) => {
                        log::debug!("TURN stream {remote_addr}: read failed: {err}");
                        return;
                    }
                };
                splitter.push(&chunk[..n]);
                loop {
                    match splitter.next_frame() {
                        Ok(Some(frame)) => {
                            if in_tx.send(frame).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(err) => {
                            log::warn!("TURN stream {remote_addr}: {err}");
                            return;
                        }
                    }
                }
            }
        });

        let writer = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                // One flush per frame: a TLS stream holds a record until it
                // is flushed; a TCP stream's flush does nothing.
                let written = async {
                    wr.write_all(&frame).await?;
                    wr.flush().await
                }
                .await;
                if let Err(err) = written {
                    log::debug!("TURN stream {remote_addr}: write failed: {err}");
                    return;
                }
            }
            // The conn was closed or dropped: the queued frames are written
            // (a deallocation, say); shut the stream down.
            let _ = wr.shutdown().await;
        });

        TurnStreamConn {
            local_addr,
            remote_addr,
            inbound: Mutex::new(in_rx),
            outbound: std::sync::Mutex::new(Some(out_tx)),
            reader,
            writer: std::sync::Mutex::new(Some(writer)),
        }
    }

    /// Wraps a connected TCP stream (Nagle's algorithm off: every frame is a
    /// small, latency-bound message).
    pub fn from_tcp(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let (local_addr, remote_addr) = (stream.local_addr()?, stream.peer_addr()?);
        Ok(Self::new(stream, local_addr, remote_addr))
    }

    /// Stops both tasks: the writer gets [`CLOSE_GRACE`] to write what is
    /// queued and shut the stream down.
    fn shut(&self) {
        self.reader.abort();
        let sender = self.outbound.lock().map(|mut s| s.take()).unwrap_or(None);
        drop(sender);
        let writer = self.writer.lock().map(|mut w| w.take()).unwrap_or(None);
        if let Some(writer) = writer {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let abort = writer.abort_handle();
                    if tokio::time::timeout(CLOSE_GRACE, writer).await.is_err() {
                        abort.abort();
                    }
                });
            } else {
                writer.abort();
            }
        }
    }
}

impl Drop for TurnStreamConn {
    fn drop(&mut self) {
        self.shut();
    }
}

fn closed() -> util::Error {
    io::Error::new(io::ErrorKind::NotConnected, "TURN stream closed").into()
}

#[async_trait]
impl Conn for TurnStreamConn {
    async fn connect(&self, addr: SocketAddr) -> std::result::Result<(), util::Error> {
        if addr == self.remote_addr {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a TURN stream is connected to its one peer",
            )
            .into())
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, util::Error> {
        let (n, _) = self.recv_from(buf).await?;
        Ok(n)
    }

    /// One frame; a frame longer than `buf` is truncated, as a datagram
    /// would be.
    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<(usize, SocketAddr), util::Error> {
        let frame = self.inbound.lock().await.recv().await.ok_or_else(closed)?;
        let n = frame.len().min(buf.len());
        buf[..n].copy_from_slice(&frame[..n]);
        Ok((n, self.remote_addr))
    }

    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, util::Error> {
        self.send_to(buf, self.remote_addr).await
    }

    /// Queues `buf` as one frame for the stream's peer (`target` is not
    /// used); drops it when the queue is full.
    async fn send_to(
        &self,
        buf: &[u8],
        _target: SocketAddr,
    ) -> std::result::Result<usize, util::Error> {
        let sender = self
            .outbound
            .lock()
            .map(|s| s.clone())
            .unwrap_or(None)
            .ok_or_else(closed)?;
        match sender.try_send(outbound_frame(buf)) {
            Ok(()) => Ok(buf.len()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::trace!(
                    "TURN stream {}: send queue full, datagram dropped",
                    self.remote_addr
                );
                Ok(buf.len())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(closed()),
        }
    }

    fn local_addr(&self) -> std::result::Result<SocketAddr, util::Error> {
        Ok(self.local_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    async fn close(&self) -> std::result::Result<(), util::Error> {
        self.shut();
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// Whether `url` is a TURN URL this module dials: `turn:` or `turns:` with
/// `transport=tcp`.
pub fn is_stream_url(url: &Url) -> bool {
    url.proto == ProtoType::Tcp && matches!(url.scheme, SchemeType::Turn | SchemeType::Turns)
}

/// Opens the stream to the TURN server of `url` — TCP for `turn:`, TLS over
/// TCP for `turns:` — within `deadline` for name resolution, connect and the
/// TLS handshake together. The server's addresses are tried IPv4 first, as
/// the UDP path binds IPv4.
///
/// A `turns:` server is accepted when it presents one of `pinned` or one of
/// the process-wide pins ([`pin_server_certs`]) byte for byte, or else a
/// certificate the webpki roots validate for the URL's host (see the module
/// documentation). `pinned` is not used for `turn:`.
pub async fn dial(
    url: &Url,
    deadline: Duration,
    pinned: &[CertificateDer<'static>],
) -> io::Result<TurnStreamConn> {
    if !is_stream_url(url) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a TURN-over-TCP/TLS URL: {url}"),
        ));
    }
    match tokio::time::timeout(deadline, dial_inner(url, pinned)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("TURN stream {url}: no connection within {deadline:?}"),
        )),
    }
}

async fn dial_inner(url: &Url, pinned: &[CertificateDer<'static>]) -> io::Result<TurnStreamConn> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await?
        .collect();
    addrs.sort_by_key(|a| a.is_ipv6());

    let mut last_err = io::Error::new(io::ErrorKind::NotFound, format!("{}: no address", url.host));
    let mut tcp = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(err) => last_err = err,
        }
    }
    let tcp = tcp.ok_or(last_err)?;

    if url.scheme == SchemeType::Turn {
        return TurnStreamConn::from_tcp(tcp);
    }

    tcp.set_nodelay(true)?;
    let (local_addr, remote_addr) = (tcp.local_addr()?, tcp.peer_addr()?);
    let server_name = ServerName::try_from(url.host.clone())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let mut pins = pinned.to_vec();
    for cert in process_pins() {
        if !pins.contains(&cert) {
            pins.push(cert);
        }
    }
    let tls = tokio_rustls::TlsConnector::from(tls_client_config(pins)?)
        .connect(server_name, tcp)
        .await?;
    Ok(TurnStreamConn::new(tls, local_addr, remote_addr))
}

/// The certificates pinned process-wide (see [`pin_server_certs`]).
static PROCESS_PINS: std::sync::Mutex<Vec<CertificateDer<'static>>> =
    std::sync::Mutex::new(Vec::new());

/// Pins `certs` (DER) for every `turns:` dial in this process, in addition
/// to each agent's `AgentConfig::turn_pinned_server_certs`: a TURN server
/// presenting one of them byte for byte is accepted without a name, chain or
/// validity check (see the module documentation).
///
/// For private deployments whose TURN server has a self-signed certificate,
/// or one from the deployment's own CA, when the `AgentConfig` is built by
/// someone else (webrtc's `SettingEngine` has no field for it). Pins are only
/// ever added, never removed: a pin admits nothing but its own certificate,
/// and two configurations in one process cannot take each other's pins away.
/// Pinning nothing leaves the webpki roots alone in force.
pub fn pin_server_certs<I>(certs: I)
where
    I: IntoIterator<Item = CertificateDer<'static>>,
{
    let mut pins = PROCESS_PINS.lock().unwrap_or_else(|e| e.into_inner());
    for cert in certs {
        if !pins.contains(&cert) {
            pins.push(cert);
        }
    }
}

/// The certificates pinned process-wide so far.
pub fn process_pins() -> Vec<CertificateDer<'static>> {
    PROCESS_PINS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// The TLS client configuration for `turns:`: rustls with the ring provider
/// (the one webrtc-dtls uses) and the Mozilla root store of webpki-roots;
/// with `pinned` certificates, a verifier that also accepts any of them
/// byte for byte ([`PinnedOrWebpki`]); no client certificate.
fn tls_client_config(
    pinned: Vec<CertificateDer<'static>>,
) -> io::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let config = if pinned.is_empty() {
        builder.with_root_certificates(roots)
    } else {
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(io::Error::other)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedOrWebpki { pinned, webpki }))
    }
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A server certificate verifier that accepts an end-entity certificate
/// equal to one of `pinned` and verifies any other with `webpki` (the
/// webpki roots, the server name, validity). The handshake signatures are
/// `webpki`'s checks in both cases: the server proves it holds the key of
/// the certificate it presented.
#[derive(Debug)]
struct PinnedOrWebpki {
    pinned: Vec<CertificateDer<'static>>,
    webpki: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedOrWebpki {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if self
            .pinned
            .iter()
            .any(|pin| pin.as_ref() == end_entity.as_ref())
        {
            return Ok(ServerCertVerified::assertion());
        }
        self.webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

/// A relay candidate's conn (the `turn` client's relay conn) together with
/// the stream its client runs on, so that closing the candidate closes the
/// stream too.
///
/// A relay candidate's `close` closes its conn and its `turn` client, and
/// neither closes the conn the client was built on; on UDP that socket goes
/// when its last reference does, on TCP and TLS an open connection to the
/// server would stay up while anything still holds the client. Closing the
/// relay conn queues the deallocation (a Refresh with lifetime 0); the
/// stream's close then writes it and shuts the stream down.
pub(crate) struct RelayConnOverStream {
    pub(crate) relay: Arc<dyn Conn + Send + Sync>,
    pub(crate) stream: Arc<dyn Conn + Send + Sync>,
}

#[async_trait]
impl Conn for RelayConnOverStream {
    async fn connect(&self, addr: SocketAddr) -> std::result::Result<(), util::Error> {
        self.relay.connect(addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, util::Error> {
        self.relay.recv(buf).await
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<(usize, SocketAddr), util::Error> {
        self.relay.recv_from(buf).await
    }

    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, util::Error> {
        self.relay.send(buf).await
    }

    async fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::result::Result<usize, util::Error> {
        self.relay.send_to(buf, target).await
    }

    fn local_addr(&self) -> std::result::Result<SocketAddr, util::Error> {
        self.relay.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.relay.remote_addr()
    }

    async fn close(&self) -> std::result::Result<(), util::Error> {
        let result = self.relay.close().await;
        let _ = self.stream.close().await;
        result
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
