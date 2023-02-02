use std::env;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Result};
use boringtun::noise::{Tunn, TunnResult};
use smoltcp::wire::{Ipv4Packet, TcpPacket, TcpSeqNumber, UdpPacket};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<()> {
    let port = env::args()
        .nth(1)
        .map(|x| x.parse::<u16>().expect("Not a valid port number."))
        .unwrap_or(51820);

    let static_private = StaticSecret::from(
        <[u8; 32]>::try_from(base64::decode(
            "qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk=",
        )?)
        .unwrap(),
    );
    let peer_static_public = PublicKey::from(
        <[u8; 32]>::try_from(base64::decode(
            "mitmV5Wo7pRJrHNAKhZEI0nzqqeO8u4fXG+zUbZEXA0=",
        )?)
        .unwrap(),
    );
    let tunn = Tunn::new(static_private, peer_static_public, None, None, 0, None).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.connect(SocketAddr::new(IpAddr::from_str("127.0.0.1")?, port))?;

    // IPv4 + UDP + data
    let udp_dgram = {
        let mut udp_dgram = Ipv4Packet::new_checked(hex::decode(
            "450000218d6600008011307f0a0000010a00002a\
04d27a69000d253f\
68656c6c6f",
        )?)?;
        let (src_addr, dst_addr) = (udp_dgram.src_addr(), udp_dgram.dst_addr());
        let mut udp_dgram_inner = UdpPacket::new_checked(udp_dgram.payload_mut())?;
        udp_dgram_inner.fill_checksum(&src_addr.into(), &dst_addr.into());
        udp_dgram.fill_checksum();
        udp_dgram
    };

    // IPv4 + TCP SYN
    let tcp_syn = {
        let mut tcp_syn = Ipv4Packet::new_checked(hex::decode(
            "45000034d97b40008006FFFF0a0000010a00002a\
cafe005012345678000000008002faf0FFFF0000020405b40103030801010402",
        )?)?;
        let (src_addr, dst_addr) = (tcp_syn.src_addr(), tcp_syn.dst_addr());
        let mut tcp_syn_inner = TcpPacket::new_checked(tcp_syn.payload_mut())?;
        tcp_syn_inner.fill_checksum(&src_addr.into(), &dst_addr.into());
        tcp_syn.fill_checksum();
        tcp_syn
    };

    let mut packets_to_do = vec![tcp_syn.into_inner(), udp_dgram.into_inner()];

    let mut buf_in = [0u8; 1500];
    let mut buf_out = [0u8; 1500];

    let mut udp_done = false;
    let mut tcp_done = false;

    while !(udp_done && tcp_done) {
        while !packets_to_do.is_empty() {
            let packet = packets_to_do.pop().unwrap();
            println!("Sending packet: {}", hex::encode(&packet));
            match tunn.encapsulate(&packet, &mut buf_out) {
                TunnResult::WriteToNetwork(b) => {
                    socket.send(b)?;
                }
                TunnResult::Done => (),
                _ => unreachable!("encapsulate"),
            };
        }

        let len = match socket.recv(&mut buf_in) {
            Ok(len) => len,
            // errno == EAGAIN / Resource Temporarily Unavailable: just try again later
            Err(err) if matches!(err.raw_os_error(), Some(11)) => continue,
            Err(err) => return Err(err.into()),
        };
        let mut result = tunn.decapsulate(None, &buf_in[..len], &mut buf_out);

        while let TunnResult::WriteToNetwork(b) = result {
            socket.send(b)?;
            result = tunn.decapsulate(None, &[0; 0], &mut buf_out);
        }

        match result {
            TunnResult::WriteToTunnelV4(buf, _) => {
                println!("Received packet: {}", hex::encode(&buf));
                if buf[9] == 0x11 && !udp_done {
                    if &buf[28..] == b"HELLO" {
                        println!("It's the UDP reply we were looking for.");
                        udp_done = true;
                    } else {
                        println!("It's an unexpected UDP packet.");
                    }
                } else if buf[9] == 0x6 && !tcp_done {
                    if buf[33] & 0x12 == 0x12 {
                        println!("It's a TCP SYN/ACK.");

                        let tcp_ack = {
                            let mut tcp_ack = Ipv4Packet::new_checked(hex::decode(
                                "45000034d97b40008006FFFF0a0000010a00002a\
cafe0050123456790000000050100204FFFF0000\
68656c6c6f20776f726c6421",
                            )?)?;

                            // Update ACK number
                            let ack = i32::from_be_bytes(buf[24..28].try_into().unwrap()) + 1;
                            let (src_addr, dst_addr) = (tcp_ack.src_addr(), tcp_ack.dst_addr());
                            let mut tcp_ack_inner = TcpPacket::new_checked(tcp_ack.payload_mut())?;
                            tcp_ack_inner.set_ack_number(TcpSeqNumber(ack));
                            tcp_ack_inner.fill_checksum(&src_addr.into(), &dst_addr.into());
                            tcp_ack.fill_checksum();
                            tcp_ack
                        };

                        packets_to_do.push(tcp_ack.into_inner());
                    } else if buf[33] & 0x10 == 0x10 {
                        if buf.len() == 40 {
                            println!("It's a TCP ACK with no data.");
                        } else if &buf[40..] == b"HELLO WORLD!" {
                            println!("It's a TCP ACK with the data we were looking for.");
                            tcp_done = true;
                        } else {
                            println!("It's a TCP packet with unexpected data.");
                        }
                    } else {
                        println!("It's an unexpected TCP packet.");
                    }
                } else {
                    println!("It's neither TCP nor UDP.");
                }
            }
            TunnResult::Done => (),
            _ => bail!("Unexpected decapsulatation result: {:?}", result),
        }
    }
    println!("All set!");
    Ok(())
}
