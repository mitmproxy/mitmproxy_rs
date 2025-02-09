mod mitmproxy_ipc;
pub use mitmproxy_ipc::*;

use crate::intercept_conf;
use std::net::{AddrParseError, IpAddr, SocketAddr};
use std::str::FromStr;

impl TryFrom<&Address> for SocketAddr {
    type Error = AddrParseError;

    fn try_from(address: &Address) -> Result<Self, Self::Error> {
        // The macOS network system extension may return IP addresses with scope string.
        let host = address.host.split('%').next().unwrap();
        let ip = IpAddr::from_str(host)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socketaddr_from_address() {
        let a = Address {
            host: "fe80::f0ff:88ff:febc:3df5".to_string(),
            port: 8080,
        };
        assert!(SocketAddr::try_from(&a).is_ok());

        let b = Address {
            host: "invalid".to_string(),
            port: 8080,
        };
        assert!(SocketAddr::try_from(&b).is_err());

        let c = Address {
            host: "fe80::f0ff:88ff:febc:3df5%awdl0".to_string(),
            port: 8080,
        };
        assert!(SocketAddr::try_from(&c).is_ok());
        assert_eq!(SocketAddr::try_from(&a), SocketAddr::try_from(&c));
    }
}
