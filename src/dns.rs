use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig};
use hickory_resolver::config::{LookupIpStrategy, ResolveHosts};
use hickory_resolver::lookup_ip::LookupIp;
pub use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
pub use hickory_resolver::proto::op::Query;
pub use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::system_conf::read_system_conf;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::LazyLock;

pub static DNS_SERVERS: LazyLock<Result<Vec<String>, NetError>> = LazyLock::new(|| {
    let (config, _opts) = read_system_conf()?;
    Ok(config
        .name_servers()
        .iter()
        .filter(|ns| {
            ns.connections
                .iter()
                .any(|c| matches!(c.protocol, ProtocolConfig::Udp))
        })
        .map(|ns| ns.ip.to_string())
        .collect::<Vec<String>>())
});

pub struct DnsResolver(TokioResolver);

impl DnsResolver {
    pub fn new(
        name_servers: Option<Vec<SocketAddr>>,
        use_hosts_file: bool,
    ) -> Result<Self, NetError> {
        let (config, mut opts) = if let Some(ns) = name_servers {
            // Try to get opts from system, but fall back gracefully if that is unavailable.
            let opts = read_system_conf().map(|r| r.1).unwrap_or_default();

            let mut conf = ResolverConfig::from_parts(None, vec![], vec![]);
            for addr in ns.into_iter() {
                let port = addr.port();
                let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
                udp.port = port;
                let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
                tcp.port = port;
                conf.add_name_server(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
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
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        *builder.options_mut() = opts;
        Ok(Self(builder.build()?))
    }

    pub async fn lookup_ip(&self, host: String) -> Result<Vec<IpAddr>, NetError> {
        self.0.lookup_ip(host).await.map(_interleave_addrinfos)
    }

    // hickory_resolver's ipv4/v6_lookup() doesn't use the hosts file for lookups but lookup_ip does,
    // so we instead filter addresses returned from lookup_ip for now
    //
    // https://github.com/hickory-dns/hickory-dns/pull/2149
    pub async fn lookup_ipv4(&self, host: String) -> Result<Vec<IpAddr>, NetError> {
        self.lookup_ipvx(host, IpAddr::is_ipv4).await
    }

    pub async fn lookup_ipv6(&self, host: String) -> Result<Vec<IpAddr>, NetError> {
        self.lookup_ipvx(host, IpAddr::is_ipv6).await
    }

    async fn lookup_ipvx<F>(&self, host: String, filter: F) -> Result<Vec<IpAddr>, NetError>
    where
        F: FnMut(&IpAddr) -> bool,
    {
        let lookup = self.0.lookup_ip(host).await?;
        let addrs: Vec<IpAddr> = lookup.iter().filter(filter).collect();

        if addrs.is_empty() {
            use hickory_resolver::net::NoRecords;
            Err(NoRecords::new(lookup.query().clone(), ResponseCode::NoError).into())
        } else {
            Ok(addrs)
        }
    }
}

fn _interleave_addrinfos(lookup_ip: LookupIp) -> Vec<IpAddr> {
    let mut addrs: Vec<IpAddr> = lookup_ip.iter().collect();
    interleave_inplace(&mut addrs, |a| a.is_ipv4());
    addrs
}

/// Reorder `items` in place so that elements matching `predicate` are interleaved
/// with non-matching ones, starting with a matching element. Leftover elements of
/// either kind are appended at the end. O(n) swaps.
pub fn interleave_inplace<T, F>(items: &mut [T], mut predicate: F)
where
    F: FnMut(&T) -> bool,
{
    let mut lookahead = 1;
    let mut expects = true;
    let mut i = 0;
    while i < items.len() {
        if predicate(&items[i]) != expects {
            let Some(off) = items[lookahead..]
                .iter()
                .position(|x| predicate(x) == expects)
            else {
                break;
            };
            lookahead += off;
            items.swap(i, lookahead);
            lookahead += 1;
            i += 2;
        } else {
            i += 1;
            expects = !expects;
            lookahead = i + 1;
        }
    }
}

#[cfg(test)]
mod tests {

    use hickory_server::proto::rr::rdata::{A, AAAA};
    use hickory_server::proto::rr::{Name, RData, Record};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;

    use hickory_server::store::in_memory::InMemoryZoneHandler;
    use hickory_server::zone_handler::{AxfrPolicy, ZoneType};

    use super::*;

    #[test]
    fn dns_servers() {
        assert!(DNS_SERVERS.as_ref().is_ok_and(|s| !s.is_empty()))
    }

    #[tokio::test]
    async fn resolver() -> anyhow::Result<()> {
        let listen_addr = test_server().await?;

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
        let mut records: InMemoryZoneHandler =
            InMemoryZoneHandler::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Deny);
        records.upsert_mut(
            Record::from_rdata(origin.clone(), 86400, RData::A(A::new(93, 184, 215, 14))),
            0,
        );
        records.upsert_mut(
            Record::from_rdata(
                origin,
                86400,
                RData::AAAA(AAAA::new(
                    0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
                )),
            ),
            0,
        );

        let mut catalog = hickory_server::zone_handler::Catalog::new();
        catalog.upsert(Name::root().into(), vec![Arc::new(records)]);

        let mut server = hickory_server::Server::new(catalog);
        server.register_socket(sock);

        tokio::spawn(async move { server.block_until_done().await });
        Ok(listen_addr)
    }

    #[test]
    fn interleave_more_matches_than_misses() {
        let mut items = vec![false, true, false, true, true];
        interleave_inplace(&mut items, |b| *b);
        assert_eq!(items, vec![true, false, true, false, true]);
    }

    #[test]
    fn interleave_more_misses_than_matches() {
        let mut items = vec![false, false, false, true];
        interleave_inplace(&mut items, |b| *b);
        assert_eq!(items, vec![true, false, false, false]);
    }

    #[test]
    fn interleave_single_kind() {
        let mut items = vec![true, true, true];
        interleave_inplace(&mut items, |b| *b);
        assert_eq!(items, vec![true, true, true]);

        let mut items = vec![false, false];
        interleave_inplace(&mut items, |b| *b);
        assert_eq!(items, vec![false, false]);
    }
}
