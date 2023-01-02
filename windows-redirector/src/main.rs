use std::net::SocketAddr;
use std::time::Duration;
use std::{env, thread};

use anyhow::{Context, Result};
use log::{debug, error, info};
use lru_time_cache::LruCache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use windivert::address::WinDivertNetworkData;
use windivert::{
    WinDivert, WinDivertEvent, WinDivertFlags, WinDivertLayer, WinDivertPacket,
    WinDivertParsedPacket,
};

use mitmproxy::packet_sources::windows::{
    InterceptConf, WindowsIpcRecv, WindowsIpcSend, CONF, IPC_BUF_SIZE,
};
use mitmproxy::process::process_name;
use mitmproxy::MAX_PACKET_SIZE;

use crate::packet::{ConnectionId, InternetPacket, TransportProtocol};

mod packet;

#[derive(Debug)]
enum Event {
    Packet(WinDivertPacket),
    Ipc(WindowsIpcSend),
}

#[derive(Debug)]
enum ConnectionState<'a> {
    Known(ConnectionAction),
    Unknown(Vec<(WinDivertNetworkData<'a>, InternetPacket)>),
}

#[derive(Debug, Clone)]
enum ConnectionAction {
    None,
    Intercept {
        pid: u32,
        process_name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    if cfg!(debug_assertions) {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
    let args: Vec<String> = env::args().collect();
    let pipe_name = args
        .get(1)
        .map(|x| x.as_str())
        .unwrap_or(r"\\.\pipe\mitmproxy-transparent-proxy");

    let ipc_client = ClientOptions::new()
        .open(pipe_name)
        .context("Cannot open pipe")?;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let (mut ipc_tx, ipc_rx) = mpsc::unbounded_channel::<WindowsIpcRecv>();

    // We currently rely on handles being automatically closed when the program exits.
    // only needed for forward mode
    // let _icmp_handle = WinDivert::new("icmp", WinDivertLayer::Network, 1042, WinDivertFlags::new().set_drop()).context("Error opening WinDivert handle")?;

    let socket_handle = WinDivert::new(
        "tcp || udp",
        WinDivertLayer::Socket,
        1041,
        WinDivertFlags::new().set_recv_only().set_sniff(),
    )?;
    let network_handle = WinDivert::new(
        "tcp || udp",
        WinDivertLayer::Network,
        1040,
        WinDivertFlags::new(),
    )?;
    let inject_handle = WinDivert::new(
        "false",
        WinDivertLayer::Network,
        1039,
        WinDivertFlags::new().set_send_only(),
    )?;

    let tx_clone = event_tx.clone();
    thread::spawn(move || relay_events(socket_handle, 0, 1 /*32*/, tx_clone));
    let tx_clone = event_tx.clone();
    thread::spawn(move || relay_events(network_handle, MAX_PACKET_SIZE, 1 /*8*/, tx_clone));

    tokio::spawn(async move {
        if let Err(e) = handle_ipc(ipc_client, ipc_rx, event_tx).await {
            error!("Error handling IPC: {}", e);
            std::process::exit(1);
        }
    });

    let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
        Duration::from_secs(60 * 10),
    );
    let mut state = InterceptConf::new(vec![], vec![], false);

    loop {
        let result = event_rx.recv().await.unwrap();
        match result {
            Event::Packet(wd_packet) => {
                match wd_packet.parse() {
                    WinDivertParsedPacket::Network { addr, data } => {
                        let packet = match InternetPacket::new(data) {
                            Ok(p) => p,
                            Err(e) => {
                                debug!("Error parsing packet: {:?}", e);
                                continue;
                            }
                        };

                        debug!(
                            "Received packet: {} {} {}",
                            packet.connection_id(),
                            packet.tcp_flag_str(),
                            packet.payload().len()
                        );

                        let is_multicast =
                            packet.src_ip().is_multicast() || packet.dst_ip().is_multicast();
                        let is_loopback_only =
                            packet.src_ip().is_loopback() && packet.dst_ip().is_loopback();
                        if is_multicast || is_loopback_only {
                            debug!(
                                "skipping multicast={} loopback={}",
                                is_multicast, is_loopback_only
                            );
                            inject_handle.send(WinDivertParsedPacket::Network {
                                addr,
                                data: packet.inner(),
                            })?;
                            continue;
                        }

                        match connections.get_mut(&packet.connection_id()) {
                            Some(state) => match state {
                                ConnectionState::Known(s) => {
                                    process_packet(addr, packet, s, &inject_handle, &mut ipc_tx)
                                        .await?;
                                }
                                ConnectionState::Unknown(packets) => {
                                    packets.push((addr, packet));
                                }
                            },
                            None => {
                                if addr.outbound() {
                                    // We expect a corresponding socket event soon.
                                    debug!("Adding unknown packet: {}", packet.connection_id());
                                    connections.insert(
                                        packet.connection_id(),
                                        ConnectionState::Unknown(vec![(addr, packet)]),
                                    );
                                } else {
                                    // A new inbound connection.
                                    // debug!("Adding inbound redirect: {}", packet.connection_id());
                                    debug!("Unimplemented: No proper handling of inbound connections yet. {}", packet.connection_id());
                                    let connection_id = packet.connection_id();
                                    insert_into_connections(
                                        &mut connections,
                                        connection_id.reverse(),
                                        ConnectionAction::None,
                                        &inject_handle,
                                        &mut ipc_tx,
                                    )
                                    .await?;
                                    insert_into_connections(
                                        &mut connections,
                                        connection_id,
                                        ConnectionAction::None,
                                        &inject_handle,
                                        &mut ipc_tx,
                                    )
                                    .await?;
                                    process_packet(
                                        addr,
                                        packet,
                                        &ConnectionAction::None,
                                        &inject_handle,
                                        &mut ipc_tx,
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                    WinDivertParsedPacket::Socket { addr } => {
                        if addr.process_id() == 4 {
                            // We get some operating system events here, which generally are not useful.
                            debug!("Skipping PID 4");
                            continue;
                        }

                        let proto = match TransportProtocol::try_from(addr.protocol()) {
                            Ok(p) => p,
                            Err(e) => {
                                info!("Error parsing packet: {:?}", e);
                                continue;
                            }
                        };
                        let connection_id = ConnectionId {
                            proto,
                            src: SocketAddr::from((addr.local_address(), addr.local_port())),
                            dst: SocketAddr::from((addr.remote_address(), addr.remote_port())),
                        };

                        if connection_id.src.ip().is_multicast()
                            || connection_id.dst.ip().is_multicast()
                        {
                            continue;
                        }

                        match addr.event() {
                            WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                                let make_entry = match connections.get(&connection_id) {
                                    None => true,
                                    Some(e) => matches!(e, ConnectionState::Unknown(_)),
                                };

                                debug!(
                                    "{:<15?} make_entry={} pid={} {}",
                                    addr.event(),
                                    make_entry,
                                    addr.process_id(),
                                    connection_id
                                );

                                if make_entry {
                                    let proc_name = process_name(addr.process_id());

                                    let action = if state.should_intercept(addr.process_id()) {
                                        ConnectionAction::Intercept {
                                            pid: addr.process_id(),
                                            process_name: proc_name.ok(),
                                        }
                                    } else {
                                        ConnectionAction::None
                                    };

                                    info!(
                                        "Adding: {} with {:?} ({:?})",
                                        &connection_id,
                                        action,
                                        addr.event()
                                    );

                                    insert_into_connections(
                                        &mut connections,
                                        connection_id.reverse(),
                                        ConnectionAction::None,
                                        &inject_handle,
                                        &mut ipc_tx,
                                    )
                                    .await?;
                                    insert_into_connections(
                                        &mut connections,
                                        connection_id,
                                        action,
                                        &inject_handle,
                                        &mut ipc_tx,
                                    )
                                    .await?;
                                }
                            }
                            WinDivertEvent::SocketClose => {
                                // We cannot clean up here because there are still final packets on connections after this event,
                                // But at least we can release memory for unknown connections.
                                if let Some(ConnectionState::Unknown(packets)) =
                                    connections.get_mut(&connection_id)
                                {
                                    packets.clear();
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => unreachable!(),
                }
            }
            Event::Ipc(WindowsIpcSend::Packet(buf)) => {
                let mut addr = WinDivertNetworkData::default();
                // if outbound is false, incoming connections are not re-injected into the right iface.
                addr.set_outbound(true);
                addr.set_ip_checksum(false);
                addr.set_tcp_checksum(false);
                addr.set_udp_checksum(false);

                let packet = match InternetPacket::new(buf) {
                    Ok(p) => p,
                    Err(e) => {
                        info!("Error parsing packet: {:?}", e);
                        continue;
                    }
                };

                info!(
                    "Injecting from IPC {} {} with outbound={} loopback={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    addr.outbound(),
                    addr.loopback()
                );

                let packet = WinDivertParsedPacket::Network {
                    addr,
                    data: packet.inner(),
                };

                inject_handle.send(packet)?;
            }
            Event::Ipc(WindowsIpcSend::SetIntercept(conf)) => {
                info!("{}", conf.description());
                state = conf;
            }
        }
    }
}

async fn handle_ipc(
    mut ipc: NamedPipeClient,
    mut ipc_rx: UnboundedReceiver<WindowsIpcRecv>,
    tx: UnboundedSender<Event>,
) -> Result<()> {
    let mut buf = [0u8; IPC_BUF_SIZE];
    loop {
        tokio::select! {
            r = ipc.read(&mut buf) => {
                match r {
                    Ok(len) if len > 0 => {
                        let Ok(call, n) = bincode::decode_from_slice(&buf[..len], CONF) else {
                            return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                        };
                        assert_eq!(n, len);
                        tx.send(Event::Ipc(call))?;
                    }
                    _ => {
                        info!("IPC read failed. Exiting.");
                        std::process::exit(0);
                    }
                }
            },
            Some(packet) = ipc_rx.recv() => {
                let len = bincode::encode_into_slice(&packet, &mut buf, CONF)?;
                ipc.write_all(&buf[..len]).await?;
            }
        }
    }
}

/// Repeatedly call WinDivertRecvExt o get packets and feed them into the channel.
fn relay_events(
    handle: WinDivert,
    buffer_size: usize,
    packet_count: usize,
    tx: UnboundedSender<Event>,
) {
    loop {
        let packets = handle.recv_ex(buffer_size, packet_count);
        match packets {
            Ok(Some(packets)) => {
                for packet in packets {
                    if let Err(_) = tx.send(Event::Packet(packet)) {
                        return; // main thread shut down.
                    }
                }
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("WinDivert Error: {:?}", err);
                std::process::exit(74);
            }
        };
    }
}

async fn insert_into_connections(
    connections: &mut LruCache<ConnectionId, ConnectionState<'_>>,
    key: ConnectionId,
    state: ConnectionAction,
    inject_handle: &WinDivert,
    ipc_tx: &mut UnboundedSender<WindowsIpcRecv>,
) -> Result<()> {
    let existing = connections.insert(key, ConnectionState::Known(state.clone()));

    if let Some(ConnectionState::Unknown(packets)) = existing {
        for (addr, p) in packets {
            process_packet(addr, p, &state, inject_handle, ipc_tx).await?;
        }
    }
    Ok(())
}

async fn process_packet(
    addr: WinDivertNetworkData<'_>,
    packet: InternetPacket,
    action: &ConnectionAction,
    inject_handle: &WinDivert,
    ipc_tx: &mut UnboundedSender<WindowsIpcRecv>,
) -> Result<()> {
    match action {
        ConnectionAction::None => {
            debug!(
                "Reinjecting {} {} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                addr.outbound(),
                addr.loopback()
            );
            inject_handle
                .send(WinDivertParsedPacket::Network {
                    addr,
                    data: packet.inner(),
                })
                .context("failed to re-inject packet")?;
        }
        ConnectionAction::Intercept { pid, process_name } => {
            debug!(
                "Intercepting into RPC {} {} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                addr.outbound(),
                addr.loopback()
            );
            ipc_tx.send(WindowsIpcRecv::Packet {
                data: packet.inner(),
                pid: *pid,
                process_name: process_name.clone(),
            })?;
        }
    }
    Ok(())
}
