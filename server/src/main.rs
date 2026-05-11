//! nat-check-server — a tiny Tokio TCP server that listens on two ports and replies
//! with a small JSON document describing the source endpoint that the kernel
//! observed for the connection. Deploy two of these on two distinct public
//! hosts and run `nat_check.py` against the four resulting endpoints to
//! classify the TCP NAT mapping behavior.
//!
//! The client speaks minimal HTTP/1.0 GET; the server doesn't care about
//! the path or method, only that *some* request arrives so it can drain
//! the receive buffer cleanly before responding.
//!
//! Usage:
//!     nat-check-server                # binds 0.0.0.0+[::]:7770 and 0.0.0.0+[::]:7771
//!     nat-check-server 8080 8081      # custom ports
//!
//! Response body (Content-Type: application/json):
//!     {"observed_ip":"1.2.3.4","observed_port":54321,"server_port":7770}

use socket2::{Domain, Protocol, Socket, Type};
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let port_a: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(7770);
    let port_b: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(7771);

    eprintln!("[nat-check-server] starting on :{port_a} and :{port_b}");

    let a4 = tokio::spawn(serve(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port_a))));
    let b4 = tokio::spawn(serve(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port_b))));
    let a6 = tokio::spawn(serve(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port_a))));
    let b6 = tokio::spawn(serve(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port_b))));
    let _ = tokio::join!(a4, b4, a6, b6);
}

fn bind_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

async fn serve(addr: SocketAddr) {
    let std_listener = match bind_listener(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[nat-check-server] bind {addr} failed: {e}");
            return;
        }
    };
    let listener = TcpListener::from_std(std_listener).expect("tokio listener from std");
    eprintln!("[nat-check-server] listening on {addr}");
    loop {
        match listener.accept().await {
            Ok((sock, peer)) => {
                tokio::spawn(handle(sock, peer, addr.port()));
            }
            Err(e) => eprintln!("[nat-check-server] accept {addr}: {e}"),
        }
    }
}

async fn handle(mut sock: TcpStream, peer: SocketAddr, server_port: u16) {
    // Read until we see the end of the HTTP headers (\r\n\r\n), or until we
    // hit a sane cap. We don't parse anything — we just need to drain the
    // request bytes so that closing the socket later doesn't race with
    // unread data and trigger a RST on some kernels.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        match sock.read(&mut tmp).await {
            Ok(0) => break, // peer closed
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let body = format!(
        r#"{{"observed_ip":"{}","observed_port":{},"server_port":{}}}"#,
        peer.ip(),
        peer.port(),
        server_port
    );

    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Connection: close\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.shutdown().await;
}
