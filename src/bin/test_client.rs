use std::env;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Result};
use boringtun::noise::{Tunn, TunnResult};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<()> {
    let port = env::args()
        .nth(1)
        .map(|x| x.parse::<u16>().expect("Not a valid port number."))
        .unwrap_or(51820);

    let static_private = StaticSecret::from(
        <[u8; 32]>::try_from(base64::decode("qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk=")?).unwrap(),
    );
    let peer_static_public =
        PublicKey::from(<[u8; 32]>::try_from(base64::decode("mitmV5Wo7pRJrHNAKhZEI0nzqqeO8u4fXG+zUbZEXA0=")?).unwrap());
    let tunn = Tunn::new(static_private, peer_static_public, None, None, 0, None).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.connect(SocketAddr::new(IpAddr::from_str("127.0.0.1")?, port))?;

    // IPv4 + UDP + data
    let udp_dgram = hex::decode(
        "450000218d6600008011307f0a0000010a00002a\
    04d27a69000d253f\
    68656c6c6f",
    )?;
    // IPv4 + TCP SYN
    let ip_hdr_tcp = hex::decode("45000034d97b40008006FFFF0a0000010a00002a")?;
    let mut tcp_syn = ip_hdr_tcp.clone();
    tcp_syn.append(&mut hex::decode(
        "cafe005012345678000000008002faf0FFFF0000020405b40103030801010402",
    )?);

    let mut packets_to_do = vec![tcp_syn, udp_dgram];

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
                },
                TunnResult::Done => (),
                _ => unreachable!("encapsulate"),
            };
        }

        let len = socket.recv(&mut buf_in)?;
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

                        let mut tcp_ack = ip_hdr_tcp.clone();
                        tcp_ack.append(&mut hex::decode(
                            "cafe0050123456790000000050100204FFFF0000\
                            68656c6c6f20776f726c6421",
                        )?);
                        // Update ACK number
                        let ack = u32::from_be_bytes(buf[24..28].try_into().unwrap()) + 1;
                        tcp_ack.splice(28..32, ack.to_be_bytes());
                        packets_to_do.push(tcp_ack);
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
            },
            TunnResult::Done => (),
            _ => bail!("Unexpected decapsulatation result: {:?}", result),
        }
    }
    println!("All set!");
    Ok(())
}
