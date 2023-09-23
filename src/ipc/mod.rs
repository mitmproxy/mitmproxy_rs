mod mitmproxy_ipc;
pub use mitmproxy_ipc::*;

use crate::intercept_conf;
use std::net::{AddrParseError, IpAddr, SocketAddr};
use std::str::FromStr;

impl TryFrom<&Address> for SocketAddr {
    type Error = AddrParseError;

    fn try_from(address: &Address) -> Result<Self, Self::Error> {
        let ip = IpAddr::from_str(&address.host)?;
        Ok(SocketAddr::from((ip, address.port as u16)))
    }
}
impl From<SocketAddr> for Address {
    fn from(val: SocketAddr) -> Self {
        Address {
            host: val.ip().to_string(),
            port: val.port() as u32,
        }
    }
}

impl From<intercept_conf::InterceptConf> for InterceptConf {
    fn from(conf: intercept_conf::InterceptConf) -> Self {
        InterceptConf {
            pids: conf.pids.into_iter().collect(),
            process_names: conf.process_names,
            invert: conf.invert,
        }
    }
}
impl From<InterceptConf> for intercept_conf::InterceptConf {
    fn from(conf: InterceptConf) -> Self {
        intercept_conf::InterceptConf::new(conf.pids, conf.process_names, conf.invert)
    }
}
