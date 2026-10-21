//! Which `net_conn` send errors the association survives.
//!
//! webrtc-sctp 0.17.2 closed the association on any error from
//! `net_conn.send`. A route flap (Wi-Fi roaming, an interface briefly down,
//! a firewall DROP on OUTPUT) makes the kernel refuse `sendto` for a moment
//! with EPERM / EACCES, ENETUNREACH, EHOSTUNREACH, ENETDOWN, EADDRNOTAVAIL,
//! ENOBUFS or EAGAIN, and closing on that ended a WebRTC data channel within
//! milliseconds of an outage the path itself would have survived. Such an
//! error now drops the packet and keeps the association: T3-rtx retransmits
//! dropped DATA, the other chunks have their own timers, and liveness is
//! judged by heartbeats and by the application.
//!
//! Every other send error stays fatal, as before: a closed DTLS or ICE
//! connection, a broken pipe, an unknown error.

use std::io;

use portable_atomic::{AtomicU64, Ordering};

static TRANSIENT_SEND_ERRORS: AtomicU64 = AtomicU64::new(0);

/// The number of packets dropped on a transient `net_conn` send error by
/// every association of this process since it started.
pub fn transient_send_errors() -> u64 {
    TRANSIENT_SEND_ERRORS.load(Ordering::Relaxed)
}

pub(crate) fn count_transient_send_error() {
    TRANSIENT_SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const ENOBUFS: i32 = 105;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const ENOBUFS: i32 = 55;
#[cfg(windows)]
const ENOBUFS: i32 = 10055; // WSAENOBUFS
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    windows
)))]
const ENOBUFS: i32 = i32::MIN; // unknown platform: never matches

fn is_transient_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::PermissionDenied // EPERM, EACCES: a firewall refusing the packet
            | io::ErrorKind::NetworkUnreachable // ENETUNREACH
            | io::ErrorKind::HostUnreachable // EHOSTUNREACH
            | io::ErrorKind::NetworkDown // ENETDOWN
            | io::ErrorKind::AddrNotAvailable // EADDRNOTAVAIL: the source address went away
            | io::ErrorKind::WouldBlock // EAGAIN
    )
}

fn is_transient_os_code(code: i32) -> bool {
    code == ENOBUFS || is_transient_kind(io::Error::from_raw_os_error(code).kind())
}

/// The OS error code of the last "(os error N)" in `text`, the form std's
/// `io::Error` displays an OS error in.
fn os_code_in_text(text: &str) -> Option<i32> {
    const MARK: &str = "(os error ";
    let at = text.rfind(MARK)? + MARK.len();
    let rest = &text[at..];
    let end = rest.find(')')?;
    rest[..end].trim().parse().ok()
}

/// Whether the `net_conn.send` error `err` is a transient refusal by the
/// network stack the association should survive.
///
/// The error is read structurally first: any `io::Error` in its source chain
/// (through `util::Error::Std`'s box, which `source()` does not follow) with
/// a transient OS code or kind. The WebRTC stack does not keep that
/// structure: webrtc-ice's `AgentConn::send` turns the socket error into
/// `io::Error::other(err.to_string())`, so on that path only the text
/// "... (os error N)" carries the code, and the code is read from it. An
/// error that names no transient code or kind is fatal.
pub(crate) fn is_transient_send_error(err: &::util::Error) -> bool {
    let mut node: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = node {
        if let Some(io_err) = e.downcast_ref::<io::Error>() {
            if let Some(code) = io_err.raw_os_error() {
                return is_transient_os_code(code);
            }
            if io_err.kind() != io::ErrorKind::Other && is_transient_kind(io_err.kind()) {
                return true;
            }
        }
        node = match e.downcast_ref::<::util::Error>() {
            Some(::util::Error::Std(boxed)) => Some(boxed.0.as_ref()),
            _ => e.source(),
        };
    }
    os_code_in_text(&err.to_string()).is_some_and(is_transient_os_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(code: i32) -> ::util::Error {
        io::Error::from_raw_os_error(code).into()
    }

    /// The WebRTC stack's shape: ICE flattens to a string, DTLS boxes it.
    fn through_webrtc_stack(socket_err: ::util::Error) -> ::util::Error {
        let flattened = ::util::Error::from(io::Error::other(socket_err.to_string()));
        ::util::Error::from_std(flattened)
    }

    #[test]
    fn route_flap_errors_are_transient() {
        // EPERM is 1 on Linux and macOS alike.
        assert!(is_transient_send_error(&os(1)));
        assert!(is_transient_send_error(&os(ENOBUFS)));
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::WouldBlock,
        ] {
            assert!(
                is_transient_send_error(&io::Error::from(kind).into()),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_code_survives_the_webrtc_stack_flattening_it() {
        let err = through_webrtc_stack(os(1));
        assert!(err.to_string().contains("(os error 1)"), "{err}");
        assert!(is_transient_send_error(&err));
        assert!(is_transient_send_error(&through_webrtc_stack(os(ENOBUFS))));
        // Boxed structurally (no flattening) is read through the box.
        assert!(is_transient_send_error(&::util::Error::from_std(os(1))));
    }

    #[test]
    fn closed_and_unknown_errors_stay_fatal() {
        // webrtc-ice AgentConn::send after the agent closed
        assert!(!is_transient_send_error(
            &io::Error::other("Conn is closed").into()
        ));
        // dtls ErrConnClosed, as its text arrives here through from_std
        assert!(!is_transient_send_error(&::util::Error::Other(
            "conn is closed".into()
        )));
        assert!(!is_transient_send_error(
            &::util::Error::ErrUseClosedNetworkConn
        ));
        assert!(!is_transient_send_error(&::util::Error::ErrAlreadyClosed));
        assert!(!is_transient_send_error(
            &io::Error::from(io::ErrorKind::BrokenPipe).into()
        ));
        assert!(!is_transient_send_error(
            &io::Error::from(io::ErrorKind::NotConnected).into()
        ));
        // EBADF (9 on Linux and macOS): the socket itself is gone
        assert!(!is_transient_send_error(&os(9)));
        assert!(!is_transient_send_error(&through_webrtc_stack(os(9))));
        assert!(!is_transient_send_error(&::util::Error::Other(
            "mpsc send: channel closed".into()
        )));
    }

    #[test]
    fn os_code_parsing() {
        assert_eq!(
            os_code_in_text("io error: Operation not permitted (os error 1)"),
            Some(1)
        );
        assert_eq!(
            os_code_in_text("x (os error 1) then (os error 65)"),
            Some(65)
        );
        assert_eq!(os_code_in_text("no code"), None);
        assert_eq!(os_code_in_text("(os error x)"), None);
    }
}
