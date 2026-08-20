use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use aya::Btf;
use aya::maps::Array;
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
use std::fs::Permissions;
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{fs, iter};
use tokio::io::AsyncReadExt;
use tokio::net::UnixDatagram;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
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
        debug!("Getting INTERCEPT_CONF map...");
        let mut intercept_conf = {
            let map = ebpf
                .map_mut("INTERCEPT_CONF")
                .context("couldn't get INTERCEPT_CONF map")?;
            Array::<_, ActionWrapper>::try_from(map)
                .context("Cannot cast INTERCEPT_CONF to Array")?
        };

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
                                    let actions = conf.actions
                                        .iter()
                                        .map(|s| Action::from(s.as_str()))
                                        .chain(iter::once(Action::None))
                                        .take(INTERCEPT_CONF_LEN as usize);
                                    for (i, action) in actions.enumerate() {
                                        intercept_conf.set(i as u32, ActionWrapper(action), 0)
                                            .context("failed to update INTERCEPT_CONF")?;
                                    }
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

    /// Regression test for: mitmproxy started as root (e.g. privileged
    /// Kubernetes container) must NOT require `sudo`.
    ///
    /// The test simulates a container image that has no `sudo` binary by
    /// running with a PATH that excludes any directory containing `sudo`.
    /// It then invokes the redirector binary directly (as root would) and
    /// verifies it starts — proving that the fix in `start_redirector` works:
    /// when `uid == 0`, the binary is launched directly without `sudo`.
    ///
    /// Requires: feature `root-tests` + runner must be root (uid 0).
    /// In CI this is achieved with:
    ///   CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E" cargo test --features root-tests
    #[cfg_attr(not(feature = "root-tests"), ignore)]
    #[tokio::test]
    async fn root_starts_redirector_without_sudo() {
        // Gate: this test only makes sense when running as root.
        let uid = unsafe { libc::getuid() };
        assert_eq!(uid, 0, "this test must run as root (uid=0), got uid={uid}");

        // Simulate a container image without sudo: remove every directory
        // that contains a `sudo` binary from PATH.
        let path_without_sudo: String = std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .filter(|dir| !std::path::Path::new(dir).join("sudo").exists())
            .collect::<Vec<_>>()
            .join(":");
        // Safety: single-threaded at this point in the test, env mutation is OK.
        unsafe { std::env::set_var("PATH", &path_without_sudo) };

        // Sanity-check: sudo must not be reachable anymore.
        let sudo_found = std::process::Command::new("which")
            .arg("sudo")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(
            !sudo_found,
            "sudo is still reachable via PATH={path_without_sudo:?}; pre-condition not met"
        );

        // The redirector binary is produced by `cargo build` in the same
        // workspace. CARGO_BIN_EXE_mitmproxy-linux-redirector is injected by
        // cargo when compiling tests that live in the same workspace as the
        // binary target.
        let redirector_exe = std::path::PathBuf::from(
            env!("CARGO_BIN_EXE_mitmproxy-linux-redirector"),
        );
        assert!(
            redirector_exe.exists(),
            "redirector binary not found at {}; run `cargo build` first",
            redirector_exe.display()
        );

        // Spawn the redirector directly (as root, no sudo).
        // We pass an intentionally non-existent pipe-dir so the process exits
        // quickly with an error, but the important thing is that it was
        // LAUNCHED — meaning no "Failed to run sudo" error occurred.
        let output = std::process::Command::new(&redirector_exe)
            .arg("/tmp/mitmproxy-root-test-nonexistent")
            .env("PATH", &path_without_sudo)
            .output()
            .expect("failed to spawn the redirector binary — did it fail because sudo was missing?");

        // The process may exit with an error (missing pipe dir / no eBPF),
        // but must NOT produce the "No such file or directory" error that
        // comes from trying to execute a missing `sudo`.
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("No such file or directory"),
            "redirector stderr contains 'No such file or directory', \
             which suggests sudo was invoked even though we are root.\n\
             stderr: {stderr}"
        );
        assert!(
            !stderr.contains("Failed to run sudo"),
            "redirector stderr contains 'Failed to run sudo' — the fix is not active.\n\
             stderr: {stderr}"
        );
    }
}
