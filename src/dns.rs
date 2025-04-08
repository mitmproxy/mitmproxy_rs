use hickory_resolver::config::NameServerConfig;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::config::{LookupIpStrategy, ResolveHosts};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::name_server::TokioConnectionProvider;
pub use hickory_resolver::proto::op::Query;
pub use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::proto::ProtoError;
use hickory_resolver::system_conf::read_system_conf;
pub use hickory_resolver::ResolveError;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::LazyLock;

pub static DNS_SERVERS: LazyLock<Result<Vec<String>, ResolveError>> = LazyLock::new(|| {
    let (config, _opts) = read_system_conf()?;
    Ok(config
        .name_servers()
        .iter()
        .filter(|ns| ns.protocol == Protocol::Udp)
        .map(|ns| ns.socket_addr.ip().to_string())
        .collect::<Vec<String>>())
});

pub struct DnsResolver(TokioResolver);

impl DnsResolver {
    pub fn new(
        name_servers: Option<Vec<SocketAddr>>,
        use_hosts_file: bool,
    ) -> Result<Self, ResolveError> {
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
        opts.use_hosts_file = if use_hosts_file {
            ResolveHosts::Always
        } else {
            ResolveHosts::Never
        };
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        *builder.options_mut() = opts;
        Ok(Self(builder.build()))
    }

    pub async fn lookup_ip(&self, host: String) -> Result<Vec<IpAddr>, ResolveError> {
        self.0.lookup_ip(host).await.map(_interleave_addrinfos)
    }

    // hickory_resolver's ipv4/v6_lookup() doesn't use the hosts file for lookups but lookup_ip does,
    // so we instead filter addresses returned from lookup_ip for now
    //
    // https://github.com/hickory-dns/hickory-dns/pull/2149
    pub async fn lookup_ipv4(&self, host: String) -> Result<Vec<IpAddr>, ResolveError> {
        self.lookup_ipvx(host, IpAddr::is_ipv4).await
    }

    pub async fn lookup_ipv6(&self, host: String) -> Result<Vec<IpAddr>, ResolveError> {
        self.lookup_ipvx(host, IpAddr::is_ipv6).await
    }

    async fn lookup_ipvx<F>(&self, host: String, filter: F) -> Result<Vec<IpAddr>, ResolveError>
    where
        F: FnMut(&IpAddr) -> bool,
    {
        let lookup = self.0.lookup_ip(host).await?;
        let addrs: Vec<IpAddr> = lookup.iter().filter(filter).collect();

        if addrs.is_empty() {
            Err(ProtoError::nx_error(
                Box::new(lookup.query().clone()),
                None,
                None,
                None,
                ResponseCode::NoError,
                true,
                None,
            )
            .into())
        } else {
            Ok(addrs)
        }
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
        let resolver = DnsResolver::new(Some(vec![listen_addr]), false)?;

        let mut results = resolver.lookup_ip("example.com.".to_string()).await?;
        assert_eq!(
            results,
            vec![
                IpAddr::from_str("93.184.215.14")?,
                IpAddr::from_str("2606:2800:21f:cb07:6820:80da:af6b:8b2c")?,
            ]
        );

        results = resolver.lookup_ipv4("example.com.".to_string()).await?;
        assert_eq!(results, vec![IpAddr::from_str("93.184.215.14")?,]);

        results = resolver.lookup_ipv6("example.com.".to_string()).await?;
        assert_eq!(
            results,
            vec![IpAddr::from_str("2606:2800:21f:cb07:6820:80da:af6b:8b2c")?,]
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
        catalog.upsert(Name::root().into(), vec![Arc::new(records)]);

        let mut server = hickory_server::ServerFuture::new(catalog);
        server.register_socket(sock);

        tokio::spawn(async move { server.block_until_done().await });
        Ok(listen_addr)
    }
}
