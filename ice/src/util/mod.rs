#[cfg(test)]
mod util_test;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use stun::agent::*;
use stun::attributes::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;
use tokio::time::Duration;
use util::vnet::net::*;
use util::Conn;

use crate::agent::agent_config::{InterfaceFilterFn, IpFilterFn};
use crate::error::*;
use crate::network_type::*;

pub fn create_addr(_network: NetworkType, ip: IpAddr, port: u16) -> SocketAddr {
    /*if network.is_tcp(){
        return &net.TCPAddr{IP: ip, Port: port}
    default:
        return &net.UDPAddr{IP: ip, Port: port}
    }*/
    SocketAddr::new(ip, port)
}

pub fn assert_inbound_username(m: &Message, expected_username: &str) -> Result<()> {
    let mut username = Username::new(ATTR_USERNAME, String::new());
    username.get_from(m)?;

    if username.to_string() != expected_username {
        return Err(Error::Other(format!(
            "{:?} expected({}) actual({})",
            Error::ErrMismatchUsername,
            expected_username,
            username,
        )));
    }

    Ok(())
}

pub fn assert_inbound_message_integrity(m: &mut Message, key: &[u8]) -> Result<()> {
    let message_integrity_attr = MessageIntegrity(key.to_vec());
    Ok(message_integrity_attr.check(m)?)
}

/// Initiates a stun requests to `server_addr` using conn, reads the response and returns the
/// `XORMappedAddress` returned by the stun server.
/// Adapted from stun v0.2.
pub async fn get_xormapped_addr(
    conn: &Arc<dyn Conn + Send + Sync>,
    server_addr: SocketAddr,
    deadline: Duration,
) -> Result<XorMappedAddress> {
    let resp = stun_request(conn, server_addr, deadline).await?;
    let mut addr = XorMappedAddress::default();
    addr.get_from(&resp)?;
    Ok(addr)
}

const MAX_MESSAGE_SIZE: usize = 1280;

/// The first retransmission timeout of a STUN binding request sent while
/// gathering: RFC 8489 sec 6.2.1 wants at least 500 ms, and RFC 8445 sec
/// 14.3 gives MAX(500 ms, Ta * number of srflx and relay candidates) while
/// gathering; each server-reflexive candidate here is gathered on its own
/// socket and transaction, so 500 ms.
pub(crate) const STUN_INITIAL_RTO: Duration = Duration::from_millis(500);

/// The most requests one STUN transaction sends (RFC 8489 sec 6.2.1, `Rc`).
pub(crate) const STUN_MAX_REQUESTS: usize = 7;

/// When each request of a STUN transaction goes out, from the first:
/// RFC 8489 sec 6.2.1's schedule, [`STUN_INITIAL_RTO`] doubled after each
/// retransmission, at most [`STUN_MAX_REQUESTS`] requests, and none at or
/// after `deadline` (zero: no deadline). With the 5 s gathering deadline:
/// 0, 0.5, 1.5 and 3.5 s.
pub(crate) fn stun_request_schedule(deadline: Duration) -> Vec<Duration> {
    let mut schedule = Vec::with_capacity(STUN_MAX_REQUESTS);
    let (mut at, mut rto) = (Duration::ZERO, STUN_INITIAL_RTO);
    while schedule.len() < STUN_MAX_REQUESTS && (deadline.is_zero() || at < deadline) {
        schedule.push(at);
        at += rto;
        rto *= 2;
    }
    schedule
}

/// Sends a STUN binding request to `server_addr` on `conn` and returns the
/// first datagram that comes back, decoded, or an error once `deadline`
/// (zero: none) has passed without one.
///
/// The request is retransmitted, with the same transaction ID, on
/// [`stun_request_schedule`] until a response arrives. webrtc-ice 0.17.2
/// sent it once: a request lost on a path that was dead when gathering
/// began (an ICE restart made during an outage) was never sent again, so a
/// path that returned a second later still gave no server-reflexive
/// candidate, and gathering ran to its deadline (5 s) while the agent
/// refused any newer restart. Now a returning path answers the next
/// retransmission, at most one RTO after it is back. A send error ends the
/// transaction as before (the `turn` client's transactions likewise).
pub async fn stun_request(
    conn: &Arc<dyn Conn + Send + Sync>,
    server_addr: SocketAddr,
    deadline: Duration,
) -> Result<Message> {
    let mut request = Message::new();
    request.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new())])?;

    let start = tokio::time::Instant::now();
    let schedule = stun_request_schedule(deadline);
    let mut bs = vec![0_u8; MAX_MESSAGE_SIZE];
    for (i, _) in schedule.iter().enumerate() {
        if i > 0 {
            log::trace!(
                "retransmitting STUN binding request to {server_addr} ({})",
                i + 1
            );
        }
        conn.send_to(&request.raw, server_addr).await?;

        // Wait for a response until the next request is due, or after the
        // last one until the deadline (forever without one).
        let until = match schedule.get(i + 1) {
            Some(next) => Some(start + *next),
            None if deadline > Duration::ZERO => Some(start + deadline),
            None => None,
        };
        let received = match until {
            Some(until) => tokio::time::timeout_at(until, conn.recv_from(&mut bs))
                .await
                .ok(),
            None => Some(conn.recv_from(&mut bs).await),
        };
        if let Some(result) = received {
            let (n, _) = result.map_err(|err| Error::Other(err.to_string()))?;
            let mut res = Message::new();
            res.raw = bs[..n].to_vec();
            res.decode()?;
            return Ok(res);
        }
    }

    Err(Error::Other(format!(
        "no STUN response from {server_addr} within {deadline:?} ({} requests)",
        schedule.len()
    )))
}

pub async fn local_interfaces(
    vnet: &Arc<Net>,
    interface_filter: &Option<InterfaceFilterFn>,
    ip_filter: &Option<IpFilterFn>,
    network_types: &[NetworkType],
    include_loopback: bool,
) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    let interfaces = vnet.get_interfaces().await;

    let (mut ipv4requested, mut ipv6requested) = (false, false);
    for typ in network_types {
        if typ.is_ipv4() {
            ipv4requested = true;
        }
        if typ.is_ipv6() {
            ipv6requested = true;
        }
    }

    for iface in interfaces {
        if let Some(filter) = interface_filter {
            if !filter(iface.name()) {
                continue;
            }
        }

        for ipnet in iface.addrs() {
            let ipaddr = ipnet.addr();

            if (!ipaddr.is_loopback() || include_loopback)
                && ((ipv4requested && ipaddr.is_ipv4()) || (ipv6requested && ipaddr.is_ipv6()))
                && ip_filter
                    .as_ref()
                    .map(|filter| filter(ipaddr))
                    .unwrap_or(true)
            {
                ips.insert(ipaddr);
            }
        }
    }

    ips
}

pub async fn listen_udp_in_port_range(
    vnet: &Arc<Net>,
    port_max: u16,
    port_min: u16,
    laddr: SocketAddr,
) -> Result<Arc<dyn Conn + Send + Sync>> {
    if laddr.port() != 0 || (port_min == 0 && port_max == 0) {
        return Ok(vnet.bind(laddr).await?);
    }
    let i = if port_min == 0 { 1 } else { port_min };
    let j = if port_max == 0 { 0xFFFF } else { port_max };
    if i > j {
        return Err(Error::ErrPort);
    }

    let port_start = rand::random::<u16>() % (j - i + 1) + i;
    let mut port_current = port_start;
    loop {
        let laddr = SocketAddr::new(laddr.ip(), port_current);
        match vnet.bind(laddr).await {
            Ok(c) => return Ok(c),
            Err(err) => log::debug!("failed to listen {laddr}: {err}"),
        };

        port_current = port_current.checked_add(1).unwrap_or(i);

        if port_current > j {
            port_current = i;
        }
        if port_current == port_start {
            break;
        }
    }

    Err(Error::ErrPort)
}

#[cfg(test)]
mod tests {
    use util::vnet::net::{Net, NetConfig};

    use crate::util::listen_udp_in_port_range;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_listen_udp_in_port_range_overflow() {
        let vnet = Arc::new(Net::new(Some(NetConfig {
            static_ips: vec![],
            static_ip: "127.0.0.1".parse().unwrap(),
        })));

        // Preemptively bind to port 65535 (u16::MAX) to ensure that listen_udp_in_port_range
        // triggers overflow logic by being unable to bind to port 65535 itself.
        let _conn = vnet
            .bind("127.0.0.1:65535".parse().unwrap())
            .await
            .expect("Expected binding to vnet to succeed");

        let port_max = u16::MAX;
        let port_min = u16::MAX;

        assert!(matches!(
            listen_udp_in_port_range(&vnet, port_max, port_min, "127.0.0.1:0".parse().unwrap())
                .await,
            Err(crate::Error::ErrPort)
        ))
    }
}
