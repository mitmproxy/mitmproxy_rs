use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use aya::Btf;
use aya::maps::{Array, HashMap, MapData};
use aya::programs::{CgroupSock, links::CgroupAttachMode};
use aya::{Ebpf, EbpfLoader};
use log::{debug, error, info, warn};
use mitmproxy::ipc::FromProxy;
use mitmproxy::ipc::{PacketWithMeta, from_proxy};
use mitmproxy::packet_sources::IPC_BUF_SIZE;
use mitmproxy::packet_sources::tun::create_tun_device;
use mitmproxy_linux_ebpf_common::{Action, INTERCEPT_CONF_LEN};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use prost::Message;
use prost::bytes::{Bytes, BytesMut};
use std::collections::HashSet;
use std::fs::Permissions;
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use std::{fs, iter};
use tokio::io::AsyncReadExt;
use tokio::net::UnixDatagram;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tun::AbstractDevice;

// We can't implement aya::Pod in mitmproxy-linux-ebpf-common, so we do it on a newtype.
// (see https://github.com/aya-rs/aya/pull/59)
#[derive(Copy, Clone)]
#[repr(transparent)]
struct ActionWrapper(Action);

unsafe impl aya::Pod for ActionWrapper {}

const BPF_PROG: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mitmproxy-linux"));
const BPF_HASH: [u8; 20] = const_sha1::sha1(BPF_PROG).as_bytes();

fn load_bpf(device_index: u32) -> Result<Ebpf> {
    debug!(
        "Loading BPF program ({:x})...",
        Bytes::from_static(&BPF_HASH)
    );
    let mut ebpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .override_global("INTERFACE_ID", &device_index, true)
        .load(BPF_PROG)
        .context("failed to load eBPF program")?;
    let logger = aya_log::EbpfLogger::init(&mut ebpf);
    if let Err(e) = &logger {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    debug!("Attaching BPF_CGROUP_INET_SOCK_CREATE program...");
    let prog: &mut CgroupSock = ebpf
        .program_mut("cgroup_sock_create")
        .context("failed to get cgroup_sock_create")?
        .try_into()?;
    // root cgroup to get all events.
    let cgroup = fs::File::open("/sys/fs/cgroup/").context("failed to open \"/sys/fs/cgroup/\"")?;
    prog.load()
        .context("failed to load cgroup_sock_create program")?;
    prog.attach(&cgroup, CgroupAttachMode::Single)
        .context("failed to attach cgroup_sock_create program")?;
    Ok(ebpf)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        //.format_target(false)
        .format_timestamp(None)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let pipe_dir = args
        .get(1)
        .map(PathBuf::from)
        .with_context(|| format!("usage: {} <pipe-dir>", args[0]))?;
    let mitmproxy_addr = pipe_dir.join("mitmproxy");
    let redirector_addr = pipe_dir.join("redirector");

    bump_memlock_rlimit();

    debug!("Creating tun device...");
    let (mut device, name) = create_tun_device(None)?;
    let device_index = device
        .tun_index()
        .context("failed to get tun device index")? as u32;
    debug!("Tun device created: {name} (id={device_index})");

    // Set up IPv6 policy-based routing so that IPv6 traffic from eBPF-bound
    // sockets is routed into the tun. IPv4 needs no such route.
    let ipv6 = ipv6::Ipv6Routes::setup(name, device_index)
        .await
        .inspect_err(|e| {
            warn!("Failed to set up IPv6 policy routing: {e:?}");
        })
        .ok();

    debug!("Connecting to {}...", mitmproxy_addr.display());
    let ipc = UnixDatagram::bind(&redirector_addr)
        .with_context(|| format!("failed to bind to {}", redirector_addr.display()))?;
    ipc.connect(&mitmproxy_addr)
        .with_context(|| format!("failed to connect to {}", mitmproxy_addr.display()))?;
    fs::set_permissions(&mitmproxy_addr, Permissions::from_mode(0o777))?;
    fs::set_permissions(&redirector_addr, Permissions::from_mode(0o777))?;
    println!("{}", redirector_addr.to_string_lossy());

    let mut main_loop = tokio::spawn(async move {
        let mut ipc_buf = Vec::with_capacity(IPC_BUF_SIZE);
        let mut dev_buf = BytesMut::with_capacity(IPC_BUF_SIZE);

        let mut ebpf = load_bpf(device_index).context("eBPF initialization failed")?;
        debug!("Getting process name maps...");
        let name_includes: HashMap<_, u32, u8> = HashMap::try_from(
            ebpf.take_map("INTERCEPT_TGID_INCLUDE")
                .context("couldn't get INTERCEPT_TGID_INCLUDE map")?,
        )
        .context("Cannot cast INTERCEPT_TGID_INCLUDE to HashMap")?;
        let name_excludes: HashMap<_, u32, u8> = HashMap::try_from(
            ebpf.take_map("INTERCEPT_TGID_EXCLUDE")
                .context("couldn't get INTERCEPT_TGID_EXCLUDE map")?,
        )
        .context("Cannot cast INTERCEPT_TGID_EXCLUDE to HashMap")?;
        debug!("Getting INTERCEPT_CONF map...");
        let mut intercept_conf = {
            let map = ebpf
                .map_mut("INTERCEPT_CONF")
                .context("couldn't get INTERCEPT_CONF map")?;
            Array::<_, ActionWrapper>::try_from(map)
                .context("Cannot cast INTERCEPT_CONF to Array")?
        };

        let (name_patterns_tx, name_patterns_rx) = watch::channel(NamePatterns::default());
        tokio::spawn(name_conf_task(
            name_includes,
            name_excludes,
            name_patterns_rx,
        ));

        loop {
            ipc_buf.clear();
            select! {
                r = ipc.recv_buf(&mut ipc_buf) => {
                    match r {
                        Ok(len) if len > 0 => {
                            let Ok(FromProxy { message: Some(message)}) = FromProxy::decode(ipc_buf.as_slice()) else {
                                return Err(anyhow!("Received invalid IPC message: {:?}", &ipc_buf[..len]));
                            };
                            // debug!("Received IPC message: {message:?}");

                            match message {
                                from_proxy::Message::Packet(packet) => {
                                    // debug!("Forwarding Packet to device: {}", packet.data.len());
                                    device.send(&packet.data).await.context("failed to send packet")?;
                                }
                                from_proxy::Message::InterceptConf(conf) => {
                                    debug!("Updating ebpf intercept conf: {conf:?}");
                                    if conf.actions.len() > INTERCEPT_CONF_LEN as usize {
                                        error!("Truncating intercept conf to {INTERCEPT_CONF_LEN} elements.");
                                    }
                                    // Process name patterns become marker actions here, the eBPF
                                    // program matches them against the tgid maps maintained by
                                    // `name_conf_task`.
                                    let actions = conf.actions
                                        .iter()
                                        .map(|s| Action::from(s.as_str()))
                                        .chain(iter::once(Action::None))
                                        .take(INTERCEPT_CONF_LEN as usize);
                                    for (i, action) in actions.enumerate() {
                                        intercept_conf.set(i as u32, ActionWrapper(action), 0)
                                            .context("failed to update INTERCEPT_CONF")?;
                                    }
                                    name_patterns_tx.send_replace(name_patterns(&conf.actions));
                                }
                            }
                        }
                        _ => {
                            info!("IPC read failed. Exiting.");
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                },
                // ... or process incoming packets
                r = device.read_buf(&mut dev_buf) => {
                    r.context("TUN read() failed")?;

                    let packet = PacketWithMeta {
                        data: dev_buf.split().freeze(),
                        tunnel_info: None,
                    };

                    packet.encode(&mut ipc_buf)?;
                    // debug!("Sending packet to proxy: {} {:?}", encoded.len(), &encoded);
                    ipc.send(ipc_buf.as_slice()).await?;

                    // Reclaim space in dev_buf.
                    drop(packet);
                    assert!(dev_buf.try_reclaim(IPC_BUF_SIZE));
                },
            }
        }
    });

    // Wait for a shutdown signal, or for the main loop to terminate on its own.
    let mut sigint =
        signal(SignalKind::interrupt()).context("failed to register SIGINT listener")?;
    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to register SIGTERM listener")?;
    let result = select! {
        _ = sigint.recv() => {
            info!("Received SIGINT, exiting.");
            Ok(())
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, exiting.");
            Ok(())
        }
        r = &mut main_loop => r.unwrap_or_else(|e| Err(anyhow!("main loop task failed: {e}"))),
    };

    if let Some(ipv6) = ipv6
        && let Err(e) = ipv6.cleanup().await
    {
        debug!("Failed to clean up IPv6 policy routing rule: {e}");
    }

    result
}

/// Bump the memlock rlimit. This is needed for older kernels that don't use the
/// new memcg based accounting, see https://lwn.net/Articles/837122/
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        info!("remove limit on locked memory failed, ret is: {ret}");
    }
}

/// Process name patterns from an intercept spec.
///
/// The eBPF program can only see the name of the thread that creates a socket, which is
/// different from the process name for most multithreaded applications. Process name
/// patterns are therefore resolved to tgid sets in userspace by `name_conf_task`, and the
/// eBPF program matches its name marker actions against those sets.
#[derive(Clone, Debug, Default)]
struct NamePatterns {
    includes: Vec<String>,
    excludes: Vec<String>,
}

impl NamePatterns {
    fn has_includes(&self) -> bool {
        !self.includes.is_empty()
    }

    fn has_excludes(&self) -> bool {
        !self.excludes.is_empty()
    }
}

/// Collect the process name patterns from intercept actions.
fn name_patterns(actions: &[String]) -> NamePatterns {
    let mut patterns = NamePatterns::default();
    for action in actions {
        let action = action.trim();
        match action.strip_prefix('!') {
            Some(name) => {
                if name.parse::<u32>().is_err() {
                    patterns.excludes.push(name.to_string());
                }
            }
            None => {
                if action.parse::<u32>().is_err() {
                    patterns.includes.push(action.to_string());
                }
            }
        }
    }
    patterns
}

/// Resolve process name patterns against a snapshot of running processes.
///
/// Pattern matching follows the `InterceptConf` semantics we use on other platforms:
/// a process matches if its name contains the pattern.
fn resolve_name_patterns(
    patterns: &NamePatterns,
    processes: &[(u32, String)],
) -> (HashSet<u32>, HashSet<u32>) {
    let mut included = HashSet::new();
    let mut excluded = HashSet::new();
    for (tgid, name) in processes {
        if patterns.includes.iter().any(|p| name.contains(p)) {
            included.insert(*tgid);
        }
        if patterns.excludes.iter().any(|p| name.contains(p)) {
            excluded.insert(*tgid);
        }
    }
    (included, excluded)
}

/// Collect the currently running processes as (tgid, process name) pairs.
///
/// The process name is the basename of /proc/<pid>/exe. Kernel threads and zombie
/// processes have no exe link and are skipped.
fn process_names() -> Vec<(u32, String)> {
    let mut processes = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return processes;
    };
    for entry in entries.flatten() {
        let Some(tgid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(path) = fs::read_link(format!("/proc/{tgid}/exe")) else {
            continue;
        };
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            processes.push((tgid, name.to_string()));
        }
    }
    processes
}

/// Sync the eBPF tgid maps with the given sets of matching processes.
fn sync_name_maps(
    includes: &mut HashMap<MapData, u32, u8>,
    excludes: &mut HashMap<MapData, u32, u8>,
    new_included: &HashSet<u32>,
    new_excluded: &HashSet<u32>,
    included: &mut HashSet<u32>,
    excluded: &mut HashSet<u32>,
) -> Result<()> {
    for tgid in included.difference(new_included) {
        includes
            .remove(tgid)
            .context("failed to update INTERCEPT_TGID_INCLUDE")?;
    }
    for tgid in new_included.difference(included) {
        includes
            .insert(*tgid, 0, 0)
            .context("failed to update INTERCEPT_TGID_INCLUDE")?;
    }
    for tgid in excluded.difference(new_excluded) {
        excludes
            .remove(tgid)
            .context("failed to update INTERCEPT_TGID_EXCLUDE")?;
    }
    for tgid in new_excluded.difference(excluded) {
        excludes
            .insert(*tgid, 0, 0)
            .context("failed to update INTERCEPT_TGID_EXCLUDE")?;
    }
    *included = new_included.clone();
    *excluded = new_excluded.clone();
    Ok(())
}

/// Update the tgid maps the eBPF program matches its name marker actions against.
fn refresh_name_maps(
    includes: &mut HashMap<MapData, u32, u8>,
    excludes: &mut HashMap<MapData, u32, u8>,
    patterns: &NamePatterns,
    included: &mut HashSet<u32>,
    excluded: &mut HashSet<u32>,
) -> Result<()> {
    let (new_included, new_excluded) = resolve_name_patterns(patterns, &process_names());
    sync_name_maps(
        includes,
        excludes,
        &new_included,
        &new_excluded,
        included,
        excluded,
    )
}

/// Interval at which we scan /proc for processes matching our name patterns. Processes
/// that start and connect within one interval are not intercepted until their next socket.
const PROCESS_SCAN_INTERVAL: Duration = Duration::from_millis(250);

/// Keep the eBPF tgid maps in sync with the processes matching our name patterns.
async fn name_conf_task(
    mut includes: HashMap<MapData, u32, u8>,
    mut excludes: HashMap<MapData, u32, u8>,
    mut rx: watch::Receiver<NamePatterns>,
) {
    let mut included = HashSet::new();
    let mut excluded = HashSet::new();
    loop {
        let patterns = rx.borrow_and_update().clone();
        if let Err(e) = refresh_name_maps(
            &mut includes,
            &mut excludes,
            &patterns,
            &mut included,
            &mut excluded,
        ) {
            error!("failed to apply process name patterns: {e}");
        }

        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        // The sender is gone, there is nothing left to do.
                        return;
                    }
                    break;
                }
                _ = tokio::time::sleep(PROCESS_SCAN_INTERVAL) => {
                    if !patterns.has_includes() && !patterns.has_excludes() {
                        continue;
                    }
                    if let Err(e) = refresh_name_maps(
                        &mut includes,
                        &mut excludes,
                        &patterns,
                        &mut included,
                        &mut excluded,
                    ) {
                        error!("failed to update process name maps: {e}");
                    }
                }
            }
        }
    }
}

/// For IPv4, just assigning the packet to the right interface is enough for it to show up
/// on the TUN device. For IPv6, the kernel requires us to set up a plausible route first.
mod ipv6 {
    use super::*;

    // Randomly chosen table ID and rule priority to avoid colliding with other tools
    // on the host. https://xkcd.com/221/
    const TUN_IPV6_PBR_TABLE: u32 = 1783940182;
    const TUN_IPV6_PBR_PRIORITY: u32 = 14285;

    pub struct Ipv6Routes {
        tun_name: String,
        handle: rtnetlink::Handle,
        task: JoinHandle<()>,
    }

    impl Ipv6Routes {
        ///   `ip -6 rule add oif <tun> lookup <table> priority <prio>`
        ///   `ip -6 route add default dev <tun> table <table>`
        pub async fn setup(tun_name: String, tun_index: u32) -> Result<Self> {
            let (conn, handle, _) =
                rtnetlink::new_connection().context("failed to create rtnetlink connection")?;
            let task = tokio::spawn(conn);

            // 1. Add the policy routing rule.
            let mut rule = handle.rule().add();
            *rule.message_mut() = pbr_rule_message(tun_name.clone());
            rule.replace()
                .execute()
                .await
                .context("failed to add IPv6 policy routing rule")?;

            // 2. Add a default route via the tun into our dedicated table.
            let route = rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new()
                .table_id(TUN_IPV6_PBR_TABLE)
                .output_interface(tun_index)
                .build();
            handle
                .route()
                .add(route)
                .replace()
                .execute()
                .await
                .context("failed to add IPv6 default route in PBR table")?;

            Ok(Self {
                handle,
                task,
                tun_name,
            })
        }

        pub async fn cleanup(self) -> Result<()> {
            self.handle
                .rule()
                .del(pbr_rule_message(self.tun_name))
                .execute()
                .await
                .context("failed to delete IPv6 policy routing rule")?;
            // The route in the dedicated table is attached to the tun and automatically
            // removed by the kernel when the device is destroyed.
            self.task.abort();
            Ok(())
        }
    }

    /// The policy routing rule shared by setup and cleanup.
    fn pbr_rule_message(tun_name: String) -> RuleMessage {
        let mut message = RuleMessage::default();
        message.header.family = netlink_packet_route::AddressFamily::Inet6;
        message.header.action = RuleAction::ToTable;
        message.attributes.push(RuleAttribute::Oifname(tun_name));
        message
            .attributes
            .push(RuleAttribute::Table(TUN_IPV6_PBR_TABLE));
        message
            .attributes
            .push(RuleAttribute::Priority(TUN_IPV6_PBR_PRIORITY));
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(not(feature = "root-tests"), ignore)]
    #[tokio::test]
    async fn bpf_load() {
        load_bpf(0).unwrap();
    }

    #[test]
    fn test_name_patterns() {
        let actions = [
            "firefox".into(),
            "!chrome".into(),
            " 42 ".into(),
            "!7".into(),
            "wget".into(),
        ];
        let patterns = name_patterns(&actions);
        assert_eq!(patterns.includes, vec!["firefox", "wget"]);
        assert_eq!(patterns.excludes, vec!["chrome"]);

        let patterns = name_patterns(&["!chrome".into()]);
        assert!(!patterns.has_includes());
        assert_eq!(patterns.excludes, vec!["chrome"]);

        assert!(!name_patterns(&["42".into(), "!7".into()]).has_includes());
        assert!(!name_patterns(&["42".into(), "!7".into()]).has_excludes());
    }

    #[test]
    fn test_resolve_name_patterns() {
        let patterns = NamePatterns {
            includes: vec!["fire".into(), "python".into()],
            excludes: vec!["chrom".into()],
        };
        let processes = vec![
            (1, "firefox".to_string()),
            (2, "chrome".to_string()),
            (3, "python3".to_string()),
        ];
        let (included, excluded) = resolve_name_patterns(&patterns, &processes);
        assert_eq!(included, HashSet::from([1, 3]));
        assert_eq!(excluded, HashSet::from([2]));
    }

    #[test]
    fn test_process_names() {
        let own_tgid = std::process::id();
        let own_name = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(process_names().contains(&(own_tgid, own_name)));
    }
}
