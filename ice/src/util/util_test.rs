use super::*;

#[tokio::test]
async fn test_local_interfaces() -> Result<()> {
    let vnet = Arc::new(Net::new(None));
    let interfaces = vnet.get_interfaces().await;
    let ips = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        false,
    )
    .await;

    let ips_with_loopback = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        true,
    )
    .await;
    assert!(ips_with_loopback.is_superset(&ips));
    assert!(!ips.iter().any(|ip| ip.is_loopback()));
    assert!(ips_with_loopback.iter().any(|ip| ip.is_loopback()));
    log::info!(
        "interfaces: {interfaces:?}, ips: {ips:?}, ips_with_loopback: {ips_with_loopback:?}"
    );
    Ok(())
}

// RFC 8489 sec 6.2.1: 500 ms doubling, at most Rc = 7 requests, none at or
// after the deadline.
#[test]
fn test_stun_request_schedule() {
    let ms = |v: Vec<Duration>| v.iter().map(|d| d.as_millis()).collect::<Vec<_>>();
    assert_eq!(
        ms(stun_request_schedule(Duration::from_secs(5))),
        vec![0, 500, 1500, 3500],
        "the gathering deadline"
    );
    assert_eq!(
        ms(stun_request_schedule(Duration::ZERO)),
        vec![0, 500, 1500, 3500, 7500, 15500, 31500],
        "no deadline: Rc requests"
    );
    assert_eq!(
        ms(stun_request_schedule(Duration::from_millis(1500))),
        vec![0, 500],
        "none at the deadline"
    );
}

/// A STUN server on loopback that drops the first `drop` requests it gets
/// and answers the rest; returns its address and the requests' transaction
/// IDs as they arrive.
async fn lossy_stun_server(
    drop: usize,
) -> Result<(
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<TransactionId>,
)> {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let addr = server.local_addr()?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        let mut seen = 0;
        while let Ok((n, from)) = server.recv_from(&mut buf).await {
            let mut req = Message::new();
            req.raw = buf[..n].to_vec();
            if req.decode().is_err() {
                continue;
            }
            let _ = tx.send(req.transaction_id);
            seen += 1;
            if seen <= drop {
                continue;
            }
            let mut res = Message::new();
            let xor = XorMappedAddress {
                ip: from.ip(),
                port: from.port(),
            };
            res.build(&[
                Box::new(req.transaction_id),
                Box::new(BINDING_SUCCESS),
                Box::new(xor),
            ])
            .unwrap();
            let _ = server.send_to(&res.raw, from).await;
        }
    });
    Ok((addr, rx))
}

// A request lost on the way is sent again, with the same transaction ID,
// one RTO later; the response to the retransmission is the result.
#[tokio::test]
async fn test_stun_request_retransmits_a_lost_request() -> Result<()> {
    let (server, mut requests) = lossy_stun_server(1).await?;
    let conn: Arc<dyn Conn + Send + Sync> =
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);

    let start = tokio::time::Instant::now();
    let addr = get_xormapped_addr(&conn, server, Duration::from_secs(5)).await?;
    let took = start.elapsed();

    assert_eq!(addr.port, conn.local_addr()?.port(), "the mapped address");
    assert!(
        took >= STUN_INITIAL_RTO && took < STUN_INITIAL_RTO * 2,
        "answered at the first retransmission: {took:?}"
    );
    let first = requests.recv().await.unwrap();
    let second = requests.recv().await.unwrap();
    assert_eq!(first, second, "a retransmission keeps the transaction ID");
    assert!(requests.try_recv().is_err(), "two requests in all");
    Ok(())
}

// A server that never answers gets the requests the schedule puts before
// the deadline, and the transaction fails at the deadline.
#[tokio::test]
async fn test_stun_request_gives_up_at_the_deadline() -> Result<()> {
    let (server, mut requests) = lossy_stun_server(usize::MAX).await?;
    let conn: Arc<dyn Conn + Send + Sync> =
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);

    let deadline = Duration::from_millis(1200);
    let start = tokio::time::Instant::now();
    let result = stun_request(&conn, server, deadline).await;
    let took = start.elapsed();

    assert!(result.is_err(), "no response: {result:?}");
    assert!(
        took >= deadline && took < deadline + Duration::from_millis(300),
        "failed at the deadline: {took:?}"
    );
    let mut sent = 0;
    while requests.try_recv().is_ok() {
        sent += 1;
    }
    assert_eq!(
        sent, 2,
        "requests at 0 and 500 ms (the next is due at 1.5 s)"
    );
    Ok(())
}
