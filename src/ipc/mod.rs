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
            default: conf.default(),
            actions: conf.actions(),
        }
    }
}

impl TryFrom<InterceptConf> for intercept_conf::InterceptConf {
    type Error = anyhow::Error;

    fn try_from(conf: InterceptConf) -> Result<Self, Self::Error> {
        intercept_conf::InterceptConf::try_from(conf.actions)
    }
}
