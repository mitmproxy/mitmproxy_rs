use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};

use internet_packet::{ConnectionId, TransportProtocol};
use log::warn;

use crate::intercept_conf::ProcessInfo;
use crate::processes::{get_process_name, PID};

const LISTENER_CONNECTION: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Keep track of all active local sockets and the associated process info.
#[derive(Default)]
pub struct ActiveSockets {
    sockets: HashMap<ConnectionId, Arc<ProcessInfo>>,
    process_info: HashMap<PID, Weak<ProcessInfo>>,
}


fn listener_to_cid(
    mut socket: SocketAddr,
    protocol: TransportProtocol,
) -> ConnectionId {
    ConnectionId {
        proto: protocol,
        src: socket,
        dst: LISTENER_CONNECTION,
    }
}

impl ActiveSockets {
    pub fn insert(
        &mut self,
        cid: ConnectionId,
        pid: PID,
    ) -> Arc<ProcessInfo> {
        let procinfo = self
            .process_info
            .get(&pid)
            .and_then(|p| p.upgrade())
            .unwrap_or_else(|| {
                let procinfo = Arc::new(ProcessInfo {
                    pid,
                    process_name: get_process_name(pid).ok(),
                });
                self.process_info.insert(pid, Arc::downgrade(&procinfo));
                procinfo
            });
        self.sockets.insert(cid, procinfo.clone());
        procinfo
    }

    pub fn remove(
        &mut self,
        cid: &ConnectionId,
    ) {
        let existing = self.sockets.remove(cid);
        if existing.is_none() {
            warn!("removing process info for non-existent socket: {:?}", cid);
        }
    }

    pub fn get(&self, cid: &ConnectionId) -> Option<&Arc<ProcessInfo>> {
        self.sockets
            .get(cid)
    }

    pub fn insert_listener(
        &mut self,
        socket: SocketAddr,
        protocol: TransportProtocol,
        pid: PID,
    ) {
        warn!("inserting listener {:?} for pid {}", listener_to_cid(socket, protocol), pid);
        self.insert(listener_to_cid(socket, protocol), pid);
    }

    pub fn remove_listener(
        &mut self,
        socket: SocketAddr,
        protocol: TransportProtocol,
    ) {
        self.remove(&listener_to_cid(socket, protocol))
    }

    pub fn get_listener(&self, socket: SocketAddr, protocol: TransportProtocol) -> Option<&Arc<ProcessInfo>> {
        let mut cid = listener_to_cid(socket, protocol);
        self.get(&cid).or_else(|| {
            cid.src.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            self.get(&cid).or_else(|| {
                cid.src.set_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
                self.get(&cid)
            })
        })
    }

    pub fn clear(&mut self) {
        self.sockets.clear();
    }
}

#[cfg(test)]
mod tests {
    use internet_packet::TransportProtocol::{Tcp, Udp};

    use super::*;

    #[test]
    fn test_active_sockets() {
        let mut sockets = ActiveSockets::default();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1235);
        let pid = std::process::id() as PID;
        sockets.insert_listener(addr, Tcp, pid);
        sockets.insert_listener(addr2, Tcp, pid);

        assert_eq!(sockets.sockets.len(), 2);
        assert_eq!(sockets.process_info.len(), 1);

        assert_eq!(sockets.get_listener(addr, Tcp).unwrap().pid, pid);
        assert_eq!(sockets.get_listener(addr2, Tcp).unwrap().pid, pid);

        assert!(sockets.get_listener(addr, Udp).is_none());
        sockets.remove_listener(addr, Tcp);
        assert!(sockets.get_listener(addr, Tcp).is_none());
    }

    #[test]
    fn test_unspecified() {
        let mut sockets = ActiveSockets::default();
        let pid = 42;

        sockets.insert_listener(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4444)), Tcp, pid);
        sockets.insert_listener(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 6666)), Tcp, pid);

        assert_eq!(sockets.get_listener(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4444)), Tcp).unwrap().pid, pid);
        assert_eq!(sockets.get_listener(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 4444)), Tcp).unwrap().pid, pid);
        assert_eq!(sockets.get_listener(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 6666)), Tcp).unwrap().pid, pid);
        assert_eq!(sockets.get_listener(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 6666)), Tcp).unwrap().pid, pid);
    }
}