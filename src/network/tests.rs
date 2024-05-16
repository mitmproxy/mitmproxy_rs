use std::net::{Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Result};
use internet_packet::InternetPacket;
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
    NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
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

    async fn push_smol_packet(&self, packet: SmolPacket) -> Result<()> {
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

    async fn pull_smol_packet(&mut self) -> SmolPacket {
        let NetworkCommand::SendPacket(packet) =
            self.smol_to_wg_rx.recv().await.expect("No packet received");
        packet
    }

    async fn pull_packet(&mut self) -> InternetPacket {
        let packet = self.pull_smol_packet().await;
        packet.try_into().unwrap()
    }

    async fn push_py_command(&self, command: TransportCommand) -> Result<()> {
        self.py_to_smol_tx.send(command)?;
        Ok(())
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
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.header_len() + payload.len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv4(ip_repr).buffer_len()];

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

    let buf = vec![0u8; IpRepr::Ipv6(ip_repr).buffer_len()];

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
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + payload.len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv4(ip_repr).buffer_len()];

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

    let buf = vec![0u8; IpRepr::Ipv6(ip_repr).buffer_len()];

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

fn build_icmp4_echo_packet(
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Ipv4Packet<Vec<u8>> {
    let icmp_repr = Icmpv4Repr::EchoRequest {
        ident,
        seq_no,
        data,
    };

    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; ip_repr.buffer_len() + icmp_repr.buffer_len()];
    let mut output_ipv4_packet = Ipv4Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_ipv4_packet, &ChecksumCapabilities::default());
    icmp_repr.emit(
        &mut Icmpv4Packet::new_unchecked(output_ipv4_packet.payload_mut()),
        &ChecksumCapabilities::default(),
    );

    output_ipv4_packet
}

fn build_icmp6_echo_packet(
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Ipv6Packet<Vec<u8>> {
    let icmp_repr = Icmpv6Repr::EchoRequest {
        ident,
        seq_no,
        data,
    };

    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 255,
    };

    let buf = vec![0u8; ip_repr.buffer_len() + icmp_repr.buffer_len()];
    let mut output_ipv6_packet = Ipv6Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_ipv6_packet);
    icmp_repr.emit(
        &src_addr,
        &dst_addr,
        &mut Icmpv6Packet::new_unchecked(output_ipv6_packet.payload_mut()),
        &ChecksumCapabilities::default(),
    );

    output_ipv6_packet
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

async fn udp_read_write(
    packet: SmolPacket,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
) -> Result<()> {
    let mut mock = MockNetwork::init().await?;

    mock.push_smol_packet(packet.clone()).await?;
    let event = mock.pull_py_event().await.unwrap();

    let TransportEvent::ConnectionEstablished {
        connection_id,
        src_addr: recv_src_addr,
        dst_addr: recv_dst_addr,
        ..
    } = event;

    assert_eq!(src_addr, recv_src_addr);
    assert_eq!(dst_addr, recv_dst_addr);

    let (tx, rx) = oneshot::channel();
    mock.push_py_command(TransportCommand::ReadData(connection_id, 0, tx))
        .await?;
    assert_eq!(rx.await?, b"hello world!");

    mock.push_py_command(TransportCommand::WriteData(
        connection_id,
        b"HELLO WORLD!".to_vec(),
    ))
    .await?;
    let response = mock.pull_packet().await;
    assert_eq!(response.payload(), b"HELLO WORLD!");
    assert_eq!(response.src(), dst_addr);
    assert_eq!(response.dst(), src_addr);

    mock.push_py_command(TransportCommand::CloseConnection(connection_id, false))
        .await?;
    mock.push_smol_packet(packet.clone()).await?;

    let (tx, rx) = oneshot::channel();
    mock.push_py_command(TransportCommand::ReadData(connection_id, 0, tx))
        .await?;
    assert!(rx.await.is_err());

    mock.stop().await
}

#[tokio::test]
async fn ipv4_udp() -> Result<()> {
    init_logger();
    let src_addr = Ipv4Address([10, 0, 0, 1]);
    let dst_addr = Ipv4Address([10, 0, 0, 42]);
    let data = "hello world!".as_bytes();

    let udp_ip_packet = build_ipv4_udp_packet(src_addr, dst_addr, 1234, 31337, data);

    udp_read_write(
        udp_ip_packet.into(),
        "10.0.0.1:1234".parse()?,
        "10.0.0.42:31337".parse()?,
    )
    .await
}

#[tokio::test]
async fn ipv6_udp() -> Result<()> {
    init_logger();

    let src: Ipv6Addr = "ca:fe:ca:fe:ca:fe:00:01".parse()?;
    let dst: Ipv6Addr = "ca:fe:ca:fe:ca:fe:00:02".parse()?;

    let src_addr = Ipv6Address::from(src);
    let dst_addr = Ipv6Address::from(dst);
    let data = "hello world!".as_bytes();

    let udp_ip_packet = build_ipv6_udp_packet(src_addr, dst_addr, 1234, 31337, data);

    udp_read_write(
        udp_ip_packet.into(),
        SocketAddr::from((src, 1234)),
        SocketAddr::from((dst, 31337)),
    )
    .await
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
    mock.push_smol_packet(tcp_ip_syn_packet.into()).await?;

    // expect TCP SYN/ACK
    let mut tcp_synack_ip_packet = match mock.pull_smol_packet().await {
        SmolPacket::V4(packet) => packet,
        SmolPacket::V6(_) => return Err(anyhow!("Received unexpected IPv6 packet!")),
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
    mock.push_smol_packet(tcp_ip_ack_packet.into()).await?;

    // expect ConnectionEstablished event
    let event = mock.pull_py_event().await.unwrap();

    let TransportEvent::ConnectionEstablished {
        connection_id: tcp_conn_id,
        src_addr: tcp_src_sock,
        dst_addr: tcp_dst_sock,
        ..
    } = event;
    assert_eq!(IpAddress::Ipv4(src_addr), tcp_src_sock.ip().into());
    assert_eq!(IpAddress::Ipv4(dst_addr), tcp_dst_sock.ip().into());

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
    mock.pull_smol_packet().await;
    mock.pull_smol_packet().await;

    let mut tcp_resp_ip_packet = match mock.pull_smol_packet().await {
        SmolPacket::V4(packet) => packet,
        SmolPacket::V6(_) => return Err(anyhow!("Received unexpected IPv6 packet!")),
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
    let mut tcp_fin_ip_packet = match mock.pull_smol_packet().await {
        SmolPacket::V4(packet) => packet,
        SmolPacket::V6(_) => return Err(anyhow!("Received unexpected IPv6 packet!")),
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
    mock.push_smol_packet(tcp_ip_syn_packet.into()).await?;

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
    mock.push_smol_packet(tcp_ip_syn_packet.into()).await?;

    // expect TCP SYN/ACK
    let mut tcp_synack_ip_packet = match mock.pull_smol_packet().await {
        SmolPacket::V6(packet) => packet,
        SmolPacket::V4(_) => return Err(anyhow!("Received unexpected IPv4 packet!")),
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
    mock.push_smol_packet(tcp_ip_ack_packet.into()).await?;

    // expect ConnectionEstablished event
    let event = mock.pull_py_event().await.unwrap();

    let TransportEvent::ConnectionEstablished {
        connection_id: tcp_conn_id,
        src_addr: tcp_src_sock,
        dst_addr: tcp_dst_sock,
        ..
    } = event;
    assert_eq!(IpAddress::Ipv6(src_addr), tcp_src_sock.ip().into());
    assert_eq!(IpAddress::Ipv6(dst_addr), tcp_dst_sock.ip().into());

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
    mock.pull_smol_packet().await;
    mock.pull_smol_packet().await;

    let mut tcp_resp_ip_packet = match mock.pull_smol_packet().await {
        SmolPacket::V6(packet) => packet,
        SmolPacket::V4(_) => return Err(anyhow!("Received unexpected IPv4 packet!")),
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
    let mut tcp_fin_ip_packet = match mock.pull_smol_packet().await {
        SmolPacket::V6(packet) => packet,
        SmolPacket::V4(_) => return Err(anyhow!("Received unexpected IPv4 packet!")),
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
    mock.push_smol_packet(tcp_ip_syn_packet.into()).await?;

    mock.stop().await
}

#[tokio::test]
async fn receive_icmp4_echo() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;

    let src_addr = Ipv4Address([10, 0, 0, 1]);
    let dst_addr = Ipv4Address([10, 0, 0, 42]);
    let data = "hello world!".as_bytes();

    let icmp_echo_ip_packet = build_icmp4_echo_packet(src_addr, dst_addr, 42, 31337, data);

    mock.push_smol_packet(icmp_echo_ip_packet.into()).await?;

    let response = mock.pull_smol_packet().await;

    if let SmolPacket::V4(mut response) = response {
        // Checking that source and destination addresses were flipped and data was the same.
        assert_eq!(src_addr, response.dst_addr());
        assert_eq!(dst_addr, response.src_addr());

        let mut input_icmpv4_packet = match Icmpv4Packet::new_checked(response.payload_mut()) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("Invalid ICMPv4 packet emitted: {}", e.to_string()));
            }
        };

        assert_eq!(input_icmpv4_packet.msg_type(), Icmpv4Message::EchoReply);
        assert_eq!(42, input_icmpv4_packet.echo_ident());
        assert_eq!(31337, input_icmpv4_packet.echo_seq_no());
        assert_eq!(data, input_icmpv4_packet.data_mut());
    } else {
        return Err(anyhow!("Wrong packet IP type emitted!"));
    }

    mock.stop().await
}

#[tokio::test]
async fn receive_icmp6_echo() -> Result<()> {
    init_logger();
    let mut mock = MockNetwork::init().await?;

    let src_addr = Ipv6Address(b"cafecafecafe0001".to_owned());
    let dst_addr = Ipv6Address(b"cafecafecafe0002".to_owned());
    let data = "hello world!".as_bytes();

    let icmp_echo_ip_packet = build_icmp6_echo_packet(src_addr, dst_addr, 42, 31337, data);

    mock.push_smol_packet(icmp_echo_ip_packet.into()).await?;

    let response = mock.pull_smol_packet().await;

    if let SmolPacket::V6(mut response) = response {
        // Checking that source and destination addresses were flipped and data was the same.
        assert_eq!(src_addr, response.dst_addr());
        assert_eq!(dst_addr, response.src_addr());

        let mut input_icmpv6_packet = match Icmpv6Packet::new_checked(response.payload_mut()) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("Invalid ICMPv6 packet emitted: {}", e.to_string()));
            }
        };

        assert_eq!(input_icmpv6_packet.msg_type(), Icmpv6Message::EchoReply);
        assert_eq!(42, input_icmpv6_packet.echo_ident());
        assert_eq!(31337, input_icmpv6_packet.echo_seq_no());
        assert_eq!(data, input_icmpv6_packet.payload_mut());
    } else {
        return Err(anyhow!("Wrong packet IP type emitted!"));
    }

    mock.stop().await
}
