use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{anyhow, Result};
use smoltcp::{phy::ChecksumCapabilities, wire::*};
use tokio::{
    sync::{
        broadcast::{self, Sender as BroadcastSender},
        mpsc::{channel, unbounded_channel, Receiver, Sender, UnboundedSender},
        oneshot,
    },
    task::JoinHandle,
};

use crate::messages::{
    IpPacket, NetworkCommand, NetworkEvent, TransportCommand, TransportEvent, TunnelInfo,
};

use super::task::NetworkTask;

struct MockNetwork {
    wg_to_smol_tx: Sender<NetworkEvent>,
    smol_to_wg_rx: Receiver<NetworkCommand>,

    py_to_smol_tx: UnboundedSender<TransportCommand>,
    smol_to_py_rx: Receiver<TransportEvent>,

    sd_trigger: BroadcastSender<()>,
    handle: JoinHandle<Result<()>>,
}

impl MockNetwork {
    async fn init() -> Result<Self> {
        let (wg_to_smol_tx, wg_to_smol_rx) = channel(16);
        let (smol_to_wg_tx, smol_to_wg_rx) = channel(16);

        let (py_to_smol_tx, py_to_smol_rx) = unbounded_channel();
        let (smol_to_py_tx, smol_to_py_rx) = channel(64);

        let (sd_trigger, sd_watcher) = broadcast::channel(1);

        let task = NetworkTask::new(
            smol_to_wg_tx,
            wg_to_smol_rx,
            smol_to_py_tx,
            py_to_smol_rx,
            sd_watcher,
        )?;

        let handle = tokio::spawn(task.run());

        Ok(Self {
            wg_to_smol_tx,
            smol_to_wg_rx,
            py_to_smol_tx,
            smol_to_py_rx,
            sd_trigger,
            handle,
        })
    }

    async fn stop(self) -> Result<()> {
        self.sd_trigger.send(())?;
        self.handle.await?
    }

    async fn push_wg_packet(&self, packet: IpPacket) -> Result<()> {
        let tunnel_info = TunnelInfo::WireGuard {
            src_addr: "192.168.86.134:12345".parse()?,
            dst_addr: "0.0.0.0:0".parse()?,
        };
        let event = NetworkEvent::ReceivePacket {
            packet,
            tunnel_info,
        };
        self.wg_to_smol_tx.send(event).await?;
        Ok(())
    }

    async fn push_py_command(&self, command: TransportCommand) -> Result<()> {
        self.py_to_smol_tx.send(command)?;
        Ok(())
    }

    async fn pull_wg_packet(&mut self) -> Option<IpPacket> {
        self.smol_to_wg_rx
            .recv()
            .await
            .map(|command| match command {
                NetworkCommand::SendPacket(packet) => packet,
            })
    }

    async fn pull_py_event(&mut self) -> Option<TransportEvent> {
        self.smol_to_py_rx.recv().await
    }
}

#[allow(clippy::too_many_arguments)]
fn build_ipv4_tcp_packet(
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    control: TcpControl,
    seq_number: TcpSeqNumber,
    ack_number: Option<TcpSeqNumber>,
    payload: &[u8],
) -> Ipv4Packet<Vec<u8>> {
    let tcp_repr = TcpRepr {
        src_port,
        dst_port,
        control,
        seq_number,
        ack_number,
        window_len: 64240,
        window_scale: Some(8),
        max_seg_size: Some(1380),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        payload,
    };

    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        protocol: IpProtocol::Tcp,
        payload_len: tcp_repr.header_len() + payload.len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv4(ip_repr).total_len()];

    let mut ip_packet = Ipv4Packet::new_unchecked(buf);
    ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());

    tcp_repr.emit(
        &mut TcpPacket::new_unchecked(ip_packet.payload_mut()),
        &ip_repr.src_addr.into(),
        &ip_repr.dst_addr.into(),
        &ChecksumCapabilities::default(),
    );

    ip_packet
}

#[allow(clippy::too_many_arguments)]
fn build_ipv6_tcp_packet(
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    src_port: u16,
    dst_port: u16,
    control: TcpControl,
    seq_number: TcpSeqNumber,
    ack_number: Option<TcpSeqNumber>,
    payload: &[u8],
) -> Ipv6Packet<Vec<u8>> {
    let tcp_repr = TcpRepr {
        src_port,
        dst_port,
        control,
        seq_number,
        ack_number,
        window_len: 64240,
        window_scale: Some(8),
        max_seg_size: Some(1380),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        payload,
    };

    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.header_len() + payload.len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv6(ip_repr).total_len()];

    let mut ip_packet = Ipv6Packet::new_unchecked(buf);
    ip_repr.emit(&mut ip_packet);

    tcp_repr.emit(
        &mut TcpPacket::new_unchecked(ip_packet.payload_mut()),
        &ip_repr.src_addr.into(),
        &ip_repr.dst_addr.into(),
        &ChecksumCapabilities::default(),
    );

    ip_packet
}

fn build_ipv4_udp_packet(
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Ipv4Packet<Vec<u8>> {
    let udp_repr = UdpRepr { src_port, dst_port };

    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        protocol: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + payload.len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv4(ip_repr).total_len()];

    let mut ip_packet = Ipv4Packet::new_unchecked(buf);
    ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());

    udp_repr.emit(
        &mut UdpPacket::new_unchecked(ip_packet.payload_mut()),
        &ip_repr.src_addr.into(),
        &ip_repr.dst_addr.into(),
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );

    ip_packet
}

fn build_ipv6_udp_packet(
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Ipv6Packet<Vec<u8>> {
    let udp_repr = UdpRepr { src_port, dst_port };

    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + payload.len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv6(ip_repr).total_len()];

    let mut ip_packet = Ipv6Packet::new_unchecked(buf);
    ip_repr.emit(&mut ip_packet);

    udp_repr.emit(
        &mut UdpPacket::new_unchecked(ip_packet.payload_mut()),
        &ip_repr.src_addr.into(),
        &ip_repr.dst_addr.into(),
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );

    ip_packet
}

fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();
}

#[tokio::test]
async fn do_nothing() -> Result<()> {
    init_logger();
    let mock = MockNetwork::init().await?;
    mock.stop().await
}

#[tokio::test]
async fn receive_ipv4_datagram() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;

    let src_addr = Ipv4Address([10, 0, 0, 1]);
    let dst_addr = Ipv4Address([10, 0, 0, 42]);
    let data = "hello world!".as_bytes();

    let udp_ip_packet = build_ipv4_udp_packet(src_addr, dst_addr, 1234, 31337, data);

    mock.push_wg_packet(udp_ip_packet.into()).await?;
    let event = mock.pull_py_event().await.unwrap();

    if let TransportEvent::DatagramReceived {
        data: recv_data,
        src_addr: recv_src_addr,
        dst_addr: recv_dst_addr,
        tunnel_info: _,
    } = event
    {
        assert_eq!(data, recv_data);
        assert_eq!(IpAddress::Ipv4(src_addr), recv_src_addr.ip().into());
        assert_eq!(IpAddress::Ipv4(dst_addr), recv_dst_addr.ip().into());
    } else {
        return Err(anyhow!("Wrong Transport event emitted!"));
    }

    mock.stop().await
}

#[tokio::test]
async fn receive_ipv6_datagram() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;

    let src_addr = Ipv6Address(b"cafecafecafe0001".to_owned());
    let dst_addr = Ipv6Address(b"cafecafecafe0002".to_owned());
    let data = "hello world!".as_bytes();

    let udp_ip_packet = build_ipv6_udp_packet(src_addr, dst_addr, 1234, 31337, data);

    mock.push_wg_packet(udp_ip_packet.into()).await?;
    let event = mock.pull_py_event().await.unwrap();

    if let TransportEvent::DatagramReceived {
        data: recv_data,
        src_addr: recv_src_addr,
        dst_addr: recv_dst_addr,
        tunnel_info: _,
    } = event
    {
        assert_eq!(data, recv_data);
        assert_eq!(IpAddress::Ipv6(src_addr), recv_src_addr.ip().into());
        assert_eq!(IpAddress::Ipv6(dst_addr), recv_dst_addr.ip().into());
    } else {
        return Err(anyhow!("Wrong Transport event emitted!"));
    }

    mock.stop().await
}

#[tokio::test]
async fn send_ipv4_datagram() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;

    let src_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Address([10, 0, 0, 42]).into(), 31337));
    let dst_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Address([10, 0, 0, 1]).into(), 1234));
    let data = "hello world!".as_bytes();

    mock.push_py_command(TransportCommand::SendDatagram {
        data: data.to_vec(),
        src_addr,
        dst_addr,
    })
    .await?;

    let mut udp_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V4(packet) => packet,
        IpPacket::V6(_) => return Err(anyhow!("Received unexpected IPv6 packet!")),
    };

    let udp_ip_src_addr = udp_ip_packet.src_addr();
    let udp_ip_dst_addr = udp_ip_packet.dst_addr();

    let udp_packet = UdpPacket::new_unchecked(udp_ip_packet.payload_mut() as &[u8]);
    let udp_repr = UdpRepr::parse(
        &udp_packet,
        &udp_ip_src_addr.into(),
        &udp_ip_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(udp_packet.payload(), data);
    assert_eq!(udp_repr.src_port, 31337);
    assert_eq!(udp_repr.dst_port, 1234);

    mock.stop().await
}

#[tokio::test]
async fn send_ipv6_datagram() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;

    let src_addr = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Address(b"cafecafecafe0001".to_owned()).into(),
        31337,
        0,
        0,
    ));
    let dst_addr = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Address(b"cafecafecafe0002".to_owned()).into(),
        1234,
        0,
        0,
    ));
    let data = "hello world!".as_bytes();

    mock.push_py_command(TransportCommand::SendDatagram {
        data: data.to_vec(),
        src_addr,
        dst_addr,
    })
    .await?;

    let mut udp_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V6(packet) => packet,
        IpPacket::V4(_) => return Err(anyhow!("Received unexpected IPv4 packet!")),
    };

    let udp_ip_src_addr = udp_ip_packet.src_addr();
    let udp_ip_dst_addr = udp_ip_packet.dst_addr();

    let udp_packet = UdpPacket::new_unchecked(udp_ip_packet.payload_mut() as &[u8]);
    let udp_repr = UdpRepr::parse(
        &udp_packet,
        &udp_ip_src_addr.into(),
        &udp_ip_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(udp_packet.payload(), data);
    assert_eq!(udp_repr.src_port, 31337);
    assert_eq!(udp_repr.dst_port, 1234);

    mock.stop().await
}

#[tokio::test]
async fn tcp_ipv4_connection() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;
    let mut seq = TcpSeqNumber(rand::random::<i32>());

    let src_addr = Ipv4Address([10, 0, 0, 1]);
    let dst_addr = Ipv4Address([10, 0, 0, 42]);
    let data = "hello world!".as_bytes();

    // send TCP SYN
    log::debug!("Sending TCP SYN");
    let tcp_ip_syn_packet = build_ipv4_tcp_packet(
        src_addr,
        dst_addr,
        1234,
        31337,
        TcpControl::Syn,
        seq,
        None,
        &[],
    );
    mock.push_wg_packet(tcp_ip_syn_packet.into()).await?;

    // expect TCP SYN/ACK
    let mut tcp_synack_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V4(packet) => packet,
        IpPacket::V6(_) => return Err(anyhow!("Received unexpected IPv6 packet!")),
    };

    let synack_src_addr = tcp_synack_ip_packet.src_addr();
    let synack_dst_addr = tcp_synack_ip_packet.dst_addr();

    let tcp_synack_repr = TcpRepr::parse(
        &TcpPacket::new_unchecked(tcp_synack_ip_packet.payload_mut()),
        &synack_src_addr.into(),
        &synack_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(tcp_synack_repr.control, TcpControl::Syn);
    assert_eq!(tcp_synack_repr.ack_number.unwrap(), seq + 1);
    let ack = tcp_synack_repr.seq_number + 1;

    // send TCP ACK
    log::debug!("Sending TCP ACK");
    seq += 1;
    let tcp_ip_ack_packet = build_ipv4_tcp_packet(
        src_addr,
        dst_addr,
        1234,
        31337,
        TcpControl::None,
        seq,
        Some(ack),
        data,
    );
    mock.push_wg_packet(tcp_ip_ack_packet.into()).await?;

    // expect ConnectionEstablished event
    let event = mock.pull_py_event().await.unwrap();

    let (tcp_conn_id, tcp_src_sock, tcp_dst_sock) = if let TransportEvent::ConnectionEstablished {
        connection_id: tcp_conn_id,
        src_addr: tcp_src_sock,
        dst_addr: tcp_dst_sock,
        tunnel_info: _,
    } = event
    {
        assert_eq!(IpAddress::Ipv4(src_addr), tcp_src_sock.ip().into());
        assert_eq!(IpAddress::Ipv4(dst_addr), tcp_dst_sock.ip().into());
        (tcp_conn_id, tcp_src_sock, tcp_dst_sock)
    } else {
        return Err(anyhow!("Wrong Transport event emitted!"));
    };

    // expect TCP data
    log::debug!("Reading from TCP stream");
    let (chan_tx, chan_rx) = oneshot::channel();
    mock.push_py_command(TransportCommand::ReadData(tcp_conn_id, 4096, chan_tx))
        .await?;

    let tcp_recv_data = chan_rx.await?;
    assert_eq!(tcp_recv_data, data);

    // send response
    log::debug!("Writing to TCP stream");
    let data_upper = data.to_ascii_uppercase();
    mock.push_py_command(TransportCommand::WriteData(tcp_conn_id, data_upper.clone()))
        .await?;

    // drain channels
    log::debug!("Draining TCP stream");
    let (drain_tx, drain_rx) = oneshot::channel();
    mock.push_py_command(TransportCommand::DrainWriter(tcp_conn_id, drain_tx))
        .await?;
    drain_rx.await?;

    // expect TCP/IP packets
    mock.pull_wg_packet().await.unwrap();
    mock.pull_wg_packet().await.unwrap();

    let mut tcp_resp_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V4(packet) => packet,
        IpPacket::V6(_) => return Err(anyhow!("Received unexpected IPv6 packet!")),
    };

    let tcp_ip_resp_src_addr = tcp_resp_ip_packet.src_addr();
    let tcp_ip_resp_dst_addr = tcp_resp_ip_packet.dst_addr();

    assert_eq!(
        IpAddress::Ipv4(tcp_ip_resp_src_addr),
        tcp_dst_sock.ip().into()
    );
    assert_eq!(
        IpAddress::Ipv4(tcp_ip_resp_dst_addr),
        tcp_src_sock.ip().into()
    );

    let tcp_resp_repr = TcpRepr::parse(
        &TcpPacket::new_unchecked(tcp_resp_ip_packet.payload_mut()),
        &tcp_ip_resp_src_addr.into(),
        &tcp_ip_resp_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(tcp_resp_repr.payload, data_upper);

    // close TCP connection
    log::debug!("Closing TCP stream");
    mock.push_py_command(TransportCommand::CloseConnection(tcp_conn_id, false))
        .await?;

    // expect TCP FIN
    let mut tcp_fin_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V4(packet) => packet,
        IpPacket::V6(_) => return Err(anyhow!("Received unexpected IPv6 packet!")),
    };

    let tcp_ip_fin_src_addr = tcp_fin_ip_packet.src_addr();
    let tcp_ip_fin_dst_addr = tcp_fin_ip_packet.dst_addr();

    assert_eq!(
        IpAddress::Ipv4(tcp_ip_fin_src_addr),
        tcp_dst_sock.ip().into()
    );
    assert_eq!(
        IpAddress::Ipv4(tcp_ip_fin_dst_addr),
        tcp_src_sock.ip().into()
    );

    let tcp_fin_repr = TcpRepr::parse(
        &TcpPacket::new_unchecked(tcp_fin_ip_packet.payload_mut()),
        &tcp_ip_fin_src_addr.into(),
        &tcp_ip_fin_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(tcp_fin_repr.control, TcpControl::Fin);
    let ack = tcp_fin_repr.seq_number + 1;

    // send TCP FIN/ACK
    log::debug!("Sending TCP FIN/ACK");
    seq += 12; // FIXME: no idea why this requires incrementing by 12 instead of 1
    let tcp_ip_syn_packet = build_ipv4_tcp_packet(
        src_addr,
        dst_addr,
        1234,
        31337,
        TcpControl::Fin,
        seq,
        Some(ack),
        &[],
    );
    mock.push_wg_packet(tcp_ip_syn_packet.into()).await?;

    mock.stop().await
}

#[tokio::test]
async fn tcp_ipv6_connection() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;
    let mut seq = TcpSeqNumber(rand::random::<i32>());

    let src_addr = Ipv6Address(b"cafecafecafe0001".to_owned());
    let dst_addr = Ipv6Address(b"cafecafecafe0002".to_owned());
    let data = "hello world!".as_bytes();

    // send TCP SYN
    log::debug!("Sending TCP SYN");
    let tcp_ip_syn_packet = build_ipv6_tcp_packet(
        src_addr,
        dst_addr,
        1234,
        31337,
        TcpControl::Syn,
        seq,
        None,
        &[],
    );
    mock.push_wg_packet(tcp_ip_syn_packet.into()).await?;

    // expect TCP SYN/ACK
    let mut tcp_synack_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V6(packet) => packet,
        IpPacket::V4(_) => return Err(anyhow!("Received unexpected IPv4 packet!")),
    };

    let synack_src_addr = tcp_synack_ip_packet.src_addr();
    let synack_dst_addr = tcp_synack_ip_packet.dst_addr();

    let tcp_synack_repr = TcpRepr::parse(
        &TcpPacket::new_unchecked(tcp_synack_ip_packet.payload_mut()),
        &synack_src_addr.into(),
        &synack_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(tcp_synack_repr.control, TcpControl::Syn);
    assert_eq!(tcp_synack_repr.ack_number.unwrap(), seq + 1);
    let ack = tcp_synack_repr.seq_number + 1;

    // send TCP ACK
    log::debug!("Sending TCP ACK");
    seq += 1;
    let tcp_ip_ack_packet = build_ipv6_tcp_packet(
        src_addr,
        dst_addr,
        1234,
        31337,
        TcpControl::None,
        seq,
        Some(ack),
        data,
    );
    mock.push_wg_packet(tcp_ip_ack_packet.into()).await?;

    // expect ConnectionEstablished event
    let event = mock.pull_py_event().await.unwrap();

    let (tcp_conn_id, tcp_src_sock, tcp_dst_sock) = if let TransportEvent::ConnectionEstablished {
        connection_id: tcp_conn_id,
        src_addr: tcp_src_sock,
        dst_addr: tcp_dst_sock,
        tunnel_info: _,
    } = event
    {
        assert_eq!(IpAddress::Ipv6(src_addr), tcp_src_sock.ip().into());
        assert_eq!(IpAddress::Ipv6(dst_addr), tcp_dst_sock.ip().into());

        (tcp_conn_id, tcp_src_sock, tcp_dst_sock)
    } else {
        return Err(anyhow!("Wrong Transport event emitted!"));
    };

    // expect TCP data
    log::debug!("Reading from TCP stream");
    let (chan_tx, chan_rx) = oneshot::channel();
    mock.push_py_command(TransportCommand::ReadData(tcp_conn_id, 4096, chan_tx))
        .await?;

    let tcp_recv_data = chan_rx.await?;
    assert_eq!(tcp_recv_data, data);

    // send response
    log::debug!("Writing to TCP stream");
    let data_upper = data.to_ascii_uppercase();
    mock.push_py_command(TransportCommand::WriteData(tcp_conn_id, data_upper.clone()))
        .await?;

    // drain channels
    log::debug!("Draining TCP stream");
    let (drain_tx, drain_rx) = oneshot::channel();
    mock.push_py_command(TransportCommand::DrainWriter(tcp_conn_id, drain_tx))
        .await?;
    drain_rx.await?;

    // expect TCP/IP packets
    mock.pull_wg_packet().await.unwrap();
    mock.pull_wg_packet().await.unwrap();

    let mut tcp_resp_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V6(packet) => packet,
        IpPacket::V4(_) => return Err(anyhow!("Received unexpected IPv4 packet!")),
    };

    let tcp_ip_resp_src_addr = tcp_resp_ip_packet.src_addr();
    let tcp_ip_resp_dst_addr = tcp_resp_ip_packet.dst_addr();

    assert_eq!(
        IpAddress::Ipv6(tcp_ip_resp_src_addr),
        tcp_dst_sock.ip().into()
    );
    assert_eq!(
        IpAddress::Ipv6(tcp_ip_resp_dst_addr),
        tcp_src_sock.ip().into()
    );

    let tcp_resp_repr = TcpRepr::parse(
        &TcpPacket::new_unchecked(tcp_resp_ip_packet.payload_mut()),
        &tcp_ip_resp_src_addr.into(),
        &tcp_ip_resp_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(tcp_resp_repr.payload, data_upper);

    // close TCP connection
    log::debug!("Closing TCP stream");
    mock.push_py_command(TransportCommand::CloseConnection(tcp_conn_id, true))
        .await?;

    // expect TCP FIN
    let mut tcp_fin_ip_packet = match mock.pull_wg_packet().await.unwrap() {
        IpPacket::V6(packet) => packet,
        IpPacket::V4(_) => return Err(anyhow!("Received unexpected IPv4 packet!")),
    };

    let tcp_ip_fin_src_addr = tcp_fin_ip_packet.src_addr();
    let tcp_ip_fin_dst_addr = tcp_fin_ip_packet.dst_addr();

    assert_eq!(
        IpAddress::Ipv6(tcp_ip_fin_src_addr),
        tcp_dst_sock.ip().into()
    );
    assert_eq!(
        IpAddress::Ipv6(tcp_ip_fin_dst_addr),
        tcp_src_sock.ip().into()
    );

    let tcp_fin_repr = TcpRepr::parse(
        &TcpPacket::new_unchecked(tcp_fin_ip_packet.payload_mut()),
        &tcp_ip_fin_src_addr.into(),
        &tcp_ip_fin_dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();

    assert_eq!(tcp_fin_repr.control, TcpControl::Fin);
    let ack = tcp_fin_repr.seq_number + 1;

    // send TCP FIN/ACK
    log::debug!("Sending TCP FIN/ACK");
    seq += 12; // FIXME: no idea why this requires incrementing by 12 instead of 1
    let tcp_ip_syn_packet = build_ipv6_tcp_packet(
        src_addr,
        dst_addr,
        1234,
        31337,
        TcpControl::Fin,
        seq,
        Some(ack),
        &[],
    );
    mock.push_wg_packet(tcp_ip_syn_packet.into()).await?;

    mock.stop().await
}
