use hickory_resolver::config::{Protocol};
use hickory_resolver::error::{ResolveResult};
pub use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{TokioAsyncResolver};
use once_cell::sync::Lazy;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::sync::Arc;
use std::sync::Mutex;

pub use hickory_resolver::config::LookupIpStrategy;
pub use hickory_resolver::error::ResolveErrorKind;
pub use hickory_resolver::proto::op::ResponseCode;



pub static DNS_SERVERS: Lazy<ResolveResult<Vec<String>>> = Lazy::new(|| {
    let (config, _opts) = read_system_conf()?;
    Ok(config
        .name_servers()
        .iter()
        .filter(|ns| ns.protocol == Protocol::Udp)
        .map(|ns| ns.socket_addr.ip().to_string())
        .collect::<Vec<String>>()
    )
});


pub async fn getaddrinfo(host: String, ip_strategy: LookupIpStrategy, use_hosts_file: bool) -> ResolveResult<Vec<IpAddr>> {
    let resolver = get_cached_resolver(ip_strategy, use_hosts_file)?;
    resolver
        .lookup_ip(host)
        .await
        .map(|resp| {
            if ip_strategy == LookupIpStrategy::Ipv4AndIpv6 {
                _interleave_addrinfos(resp)
            } else {
                resp.into_iter().collect()
            }
        })
}

fn get_cached_resolver(ip_strategy: LookupIpStrategy, use_hosts_file: bool) -> ResolveResult<Arc<TokioAsyncResolver>> {
    // LookupIpStrategy does not derive Hash, so we just go with a vec.
    static RESOLVER: OnceLock<Mutex<Vec<(LookupIpStrategy, bool, Arc<TokioAsyncResolver>)>>> = OnceLock::new();

    let mut map = RESOLVER.get_or_init(Default::default).lock().unwrap();
    for (s, u, resolver) in map.iter() {
        if ip_strategy == *s && use_hosts_file == *u {
            return Ok(resolver.clone())
        }
    }

    let (config, mut opts) = read_system_conf()?;
    opts.use_hosts_file = use_hosts_file;
    opts.ip_strategy = ip_strategy;
    let resolver = Arc::new(TokioAsyncResolver::tokio(config, opts));
    map.push((ip_strategy, use_hosts_file, resolver.clone()));
    Ok(resolver)
}



fn _interleave_addrinfos(lookup_ip: LookupIp) -> Vec<IpAddr> {
    let (mut ipv4_addrs, mut ipv6_addrs): (Vec<IpAddr>, Vec<IpAddr>) = lookup_ip
        .into_iter()
        .partition(|addr| addr.is_ipv4());

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
