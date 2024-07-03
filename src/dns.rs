use hickory_resolver::config::LookupIpStrategy;
use hickory_resolver::error::ResolveResult;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use std::net::SocketAddr;

use hickory_resolver::config::NameServerConfig;
use hickory_resolver::config::Protocol;
use hickory_resolver::config::ResolverConfig;
pub use hickory_resolver::error::ResolveErrorKind;
pub use hickory_resolver::proto::op::ResponseCode;

pub static DNS_SERVERS: Lazy<ResolveResult<Vec<String>>> = Lazy::new(|| {
    let (config, _opts) = read_system_conf()?;
    Ok(config
        .name_servers()
        .iter()
        .filter(|ns| ns.protocol == Protocol::Udp)
        .map(|ns| ns.socket_addr.ip().to_string())
        .collect::<Vec<String>>())
});

pub struct DnsResolver(TokioAsyncResolver);

impl DnsResolver {
    pub fn new(name_servers: Option<Vec<SocketAddr>>, use_hosts_file: bool) -> ResolveResult<Self> {
        let (config, mut opts) = if let Some(ns) = name_servers {
            // Try to get opts from system, but fall back gracefully if that is unavailable.
            let opts = read_system_conf().map(|r| r.1).unwrap_or_default();

            let mut conf = ResolverConfig::new();
            for addr in ns.into_iter() {
                conf.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
                conf.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
            }
            (conf, opts)
        } else {
            read_system_conf()?
        };
        opts.use_hosts_file = use_hosts_file;
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        Ok(Self(TokioAsyncResolver::tokio(config, opts)))
    }

    pub async fn lookup_ip(&self, host: String) -> ResolveResult<Vec<IpAddr>> {
        self.0.lookup_ip(host).await.map(_interleave_addrinfos)
    }
}

fn _interleave_addrinfos(lookup_ip: LookupIp) -> Vec<IpAddr> {
    let (mut ipv4_addrs, mut ipv6_addrs): (Vec<IpAddr>, Vec<IpAddr>) =
        lookup_ip.into_iter().partition(|addr| addr.is_ipv4());

    let mut interleaved: Vec<IpAddr> = Vec::with_capacity(ipv4_addrs.len() + ipv6_addrs.len());

    while let Some(ipv4) = ipv4_addrs.pop() {
        interleaved.push(ipv4);
        if let Some(ipv6) = ipv6_addrs.pop() {
            interleaved.push(ipv6);
        }
    }
    interleaved.append(&mut ipv6_addrs);
    interleaved
}

#[cfg(test)]
mod tests {

    use hickory_resolver::config::NameServerConfig;

    use hickory_server::proto::rr::rdata::{A, AAAA};
    use hickory_server::proto::rr::{DNSClass, Name, RData, Record};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;

    use hickory_server::authority::ZoneType;
    use hickory_server::store::in_memory::InMemoryAuthority;

    use super::*;

    #[test]
    fn dns_servers() {
        assert!(DNS_SERVERS.as_ref().is_ok_and(|s| !s.is_empty()))
    }

    #[tokio::test]
    async fn resolver() -> anyhow::Result<()> {
        let listen_addr = test_server().await?;

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(listen_addr, Protocol::Udp));
        let results = DnsResolver::new(Some(vec![listen_addr]), false)?
            .lookup_ip("example.com.".to_string())
            .await?;

        assert_eq!(
            results,
            vec![
                IpAddr::from_str("93.184.215.14")?,
                IpAddr::from_str("2606:2800:21f:cb07:6820:80da:af6b:8b2c")?,
            ]
        );

        Ok(())
    }

    async fn test_server() -> anyhow::Result<SocketAddr> {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let listen_addr = sock.local_addr()?;

        let origin: Name = Name::parse("example.com.", None).unwrap();
        let mut records = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);
        records.upsert_mut(
            Record::from_rdata(origin.clone(), 86400, RData::A(A::new(93, 184, 215, 14)))
                .set_dns_class(DNSClass::IN)
                .clone(),
            0,
        );
        records.upsert_mut(
            Record::from_rdata(
                origin,
                86400,
                RData::AAAA(AAAA::new(
                    0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
                )),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
            0,
        );

        let mut catalog = hickory_server::authority::Catalog::new();
        catalog.upsert(Name::root().into(), Box::new(Arc::new(records)));

        let mut server = hickory_server::ServerFuture::new(catalog);
        server.register_socket(sock);

        tokio::spawn(async move { server.block_until_done().await });
        Ok(listen_addr)
    }
}
