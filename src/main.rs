use anyhow::anyhow;
use std::net::SocketAddr;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};

#[allow(unused)]
mod tcp;

mod wg;
use wg::WgServer;

/*
    let src_ip = ip_packet.src_addr();
    let dst_ip = ip_packet.dst_addr();

    log::debug!("WireGuard: IPv4 src address: {}", src_ip);
    log::debug!("WireGuard: IPv4 dst address: {}", dst_ip);

    let tcp_packet = TcpPacket::new_checked(ip_packet.payload_mut()).unwrap();
    log::debug!("TCP packet: {:?}", &tcp_packet);

    let src_sock_addr = SocketAddr::new(IpAddr::V4(src_ip.into()), tcp_packet.src_port());
    let dst_sock_addr = SocketAddr::new(IpAddr::V4(dst_ip.into()), tcp_packet.dst_port());

    if tcp_packet.syn() {
        log::debug!("TCP SYN: {}", dst_sock_addr);

        let mut tcp_socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; 4096]),
            TcpSocketBuffer::new(vec![0u8; 4096]),
        );
        tcp_socket.set_ack_delay(None);
        tcp_socket.listen(dst_sock_addr).unwrap();
        iface.add_socket(tcp_socket);
    }

    let mut recv_buf: Vec<u8> = Vec::new();
    iface.device_mut().recv_packet(recv_buf);

    //let res = iface.poll(Instant::now()).unwrap();

    while let Some(vec) = iface.device_mut().send_packet() {
        let mut send_buf = [0u8; 1500];

        let mut send_packet = tun.encapsulate(&recv_buf, &mut send_buf);

        match send_packet {
            TunnResult::Done => log::debug!("WireGuard: Done"),
            TunnResult::Err(e) => log::error!("WireGuard: Error {:?}", e),
            TunnResult::WriteToNetwork(b) => {
                wg_socket.send_to(b, addr).await.unwrap();
            },
            _ => unreachable!(),
        }
    }

    if tcp_packet.fin() {
        log::debug!("TCP FIN: {}", dst_sock_addr);
        tcp_connections.remove(&dst_sock_addr);
    }

    if tcp_packet.ack() {
        log::debug!("TCP ACK: {}", dst_sock_addr);

        if tcp_connections.contains(&dst_sock_addr) {
            // TODO: this does not work
            mp_socket.try_write(tcp_packet.into_inner()).unwrap();
        } else {
            log::debug!("TCP ACK for unknown destination");
        }
    }

    // TODO: handle other TCP packet types (?)
*/

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // TODO: lower default verbosity to LevelFilter::Info
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .parse_env("MG_LOG")
        .init();

    // TODO: make configurable
    let server_priv_key: X25519SecretKey = "c72d788fd0916b1185177fd7fa392451192773c889d17ac739571a63482c18bb"
        .parse()
        .map_err(|error: &str| anyhow!(error))?;

    // TODO: make configurable
    let peer_pub_key: X25519PublicKey = "DbwqnNYZWk5e19uuSR6WomO7VPaVbk/uKhmyFEnXdH8="
        .parse()
        .map_err(|error: &str| anyhow!(error))?;

    // TODO: make configurable
    let server_addr: SocketAddr = "0.0.0.0:51820".parse()?;

    let mut wg_server = WgServer::new(server_addr, server_priv_key);
    wg_server.add_peer(peer_pub_key)?;

    // start WireGuard server
    wg_server.serve().await
}
