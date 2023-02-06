use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Result};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, MAX_PATH, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_NATIVE, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::intercept_conf::PID;

pub fn get_process_name(pid: PID) -> Result<String> {
    let mut buffer = [0u16; MAX_PATH as usize];
    let path = PWSTR(buffer.as_mut_ptr());
    let mut len = buffer.len() as u32;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        // K32GetProcessImageFileNameW(handle, &mut buffer);
        let query_ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, path, &mut len)
            .ok()
            .or_else(|_|
                // WSL wants PROCESS_NAME_NATIVE, see https://github.com/microsoft/WSL/issues/3478
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_NATIVE,
                    path,
                    &mut len,
                ).ok());
        CloseHandle(handle).ok()?;
        // checking for success only after closing the handle.
        query_ok?;
        path.to_string().map_err(|e| anyhow!(e))
    }
}

#[derive(Debug, Clone)]
pub struct NetworkTableEntry {
    pub protocol: u8,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub pid: u32,
}

/// Return _all_ active listeners/connections for {TCP, UDP} x {IPv4, IPv6}.
pub fn network_table() -> Result<Vec<NetworkTableEntry>> {
    let mut entries = Vec::new();

    let mut buf = Vec::with_capacity(16384);
    let mut buf_size = 0;

    /* TCP IPv4 */
    loop {
        let res = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut buf_size,
                false,
                AF_INET.0.into(),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if res == ERROR_INSUFFICIENT_BUFFER.0 {
            buf.resize(buf.len() * 2, 0);
        } else if res == NO_ERROR.0 {
            break;
        } else {
            return Err(anyhow!("failed to get tcp table"));
        }
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    for i in 0..table.dwNumEntries {
        let row =
            unsafe { &*((table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID).add(i as usize)) };
        let local_addr = SocketAddr::new(
            Ipv4Addr::from(row.dwLocalAddr.to_be()).into(),
            (row.dwLocalPort as u16).to_be(),
        );
        let remote_addr = SocketAddr::new(
            Ipv4Addr::from(row.dwRemoteAddr.to_be()).into(),
            (row.dwRemotePort as u16).to_be(),
        );
        entries.push(NetworkTableEntry {
            protocol: 0x06,
            pid: row.dwOwningPid,
            local_addr,
            remote_addr,
        });
    }

    /* TCP IPv6 */
    loop {
        let res = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut buf_size,
                false,
                AF_INET6.0.into(),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if res == ERROR_INSUFFICIENT_BUFFER.0 {
            buf.resize(buf.len() * 2, 0);
        } else if res == NO_ERROR.0 {
            break;
        } else {
            return Err(anyhow!("failed to get tcp6 table"));
        }
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    for i in 0..table.dwNumEntries {
        let row =
            unsafe { &*((table.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID).add(i as usize)) };
        let local_addr = SocketAddr::new(
            Ipv6Addr::from(row.ucLocalAddr).into(),
            (row.dwLocalPort as u16).to_be(),
        );
        let remote_addr = SocketAddr::new(
            Ipv6Addr::from(row.ucRemoteAddr).into(),
            (row.dwRemotePort as u16).to_be(),
        );
        entries.push(NetworkTableEntry {
            protocol: 0x06,
            pid: row.dwOwningPid,
            local_addr,
            remote_addr,
        });
    }

    /* UDP IPv4 */
    loop {
        let res = unsafe {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut buf_size,
                false,
                AF_INET.0.into(),
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if res == ERROR_INSUFFICIENT_BUFFER.0 {
            buf.resize(buf.len() * 2, 0);
        } else if res == NO_ERROR.0 {
            break;
        } else {
            return Err(anyhow!("failed to get udp table"));
        }
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    for i in 0..table.dwNumEntries {
        let row =
            unsafe { &*((table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID).add(i as usize)) };
        let local_addr = SocketAddr::new(
            Ipv4Addr::from(row.dwLocalAddr.to_be()).into(),
            (row.dwLocalPort as u16).to_be(),
        );
        let remote_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        entries.push(NetworkTableEntry {
            protocol: 0x11,
            pid: row.dwOwningPid,
            local_addr,
            remote_addr,
        });
    }

    /* UDP IPv6 */
    loop {
        let res = unsafe {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut buf_size,
                false,
                AF_INET6.0.into(),
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if res == ERROR_INSUFFICIENT_BUFFER.0 {
            buf.resize(buf.len() * 2, 0);
        } else if res == NO_ERROR.0 {
            break;
        } else {
            return Err(anyhow!("failed to get udp6 table"));
        }
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    for i in 0..table.dwNumEntries {
        let row =
            unsafe { &*((table.table.as_ptr() as *const MIB_UDP6ROW_OWNER_PID).add(i as usize)) };
        let local_addr = SocketAddr::new(
            Ipv6Addr::from(row.ucLocalAddr).into(),
            (row.dwLocalPort as u16).to_be(),
        );
        let remote_addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0);
        entries.push(NetworkTableEntry {
            protocol: 0x11,
            pid: row.dwOwningPid,
            local_addr,
            remote_addr,
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn get_process_name() {
        let name = super::get_process_name(std::process::id()).unwrap();
        assert!(name.contains("mitmproxy"));
    }

    #[test]
    fn network_table() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        let table = super::network_table().unwrap();
        println!("{table:#?}");

        let tcp_port = tcp_listener.local_addr().unwrap().port();
        let tcp_pid = table
            .iter()
            .find(|conn| conn.local_addr.port() == tcp_port)
            .unwrap()
            .pid;
        assert_eq!(tcp_pid, std::process::id());

        let udp_port = udp_socket.local_addr().unwrap().port();
        let udp_pid = table
            .iter()
            .find(|conn| conn.local_addr.port() == udp_port)
            .unwrap()
            .pid;
        assert_eq!(udp_pid, std::process::id());
    }
}
