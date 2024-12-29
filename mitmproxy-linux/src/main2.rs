use std::{fs, iter};
use std::fs::Permissions;
use anyhow::Context;
use anyhow::anyhow;
use aya::EbpfLoader;
use aya::maps::Array;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use aya::Btf;
use aya::programs::{links::CgroupAttachMode, CgroupSock};
use log::{debug, warn, info, error};
use prost::bytes::BytesMut;
use tokio::net::UnixDatagram;
use tokio::select;
use mitmproxy::packet_sources::tun::create_tun_device;
use tun::AbstractDevice;
use prost::Message;
use tokio::io::AsyncReadExt;
use mitmproxy::ipc::{PacketWithMeta, from_proxy};
use mitmproxy::ipc::FromProxy;
use mitmproxy::packet_sources::IPC_BUF_SIZE;
use mitmproxy_linux_ebpf_common::{Action, INTERCEPT_CONF_LEN};

// We can't implement aya::Pod in mitmproxy-linux-ebpf-common, so we do it on a newtype.
// (see https://github.com/aya-rs/aya/pull/59)
#[derive(Copy, Clone)]
#[repr(transparent)]
struct ActionWrapper(Action);

unsafe impl aya::Pod for ActionWrapper {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    )
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

    info!("Creating tun device...");
    let (mut device, name) = create_tun_device(None)?;
    let device_index = device.tun_index().context("failed to get tun device index")? as u32;
    info!("Tun device created: {name} (id={device_index})");

    info!("Loading BPF program...");
    let mut ebpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global("INTERFACE_ID", &device_index, true)
        .load(
            aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mitmproxy-linux"))
        )?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    info!("Attaching BPF_CGROUP_INET_SOCK_CREATE program...");
    let prog: &mut CgroupSock = ebpf.program_mut("cgroup_sock_create").context("failed to get cgroup_sock_create")?.try_into()?;
    // root cgroup to get all events.
    let cgroup = std::fs::File::open("/sys/fs/cgroup/")?;
    prog.load()?;
    prog.attach(&cgroup, CgroupAttachMode::Single)?;

    info!("Getting INTERCEPT_CONF map...");
    let mut intercept_conf = {
        let map = ebpf.map_mut("INTERCEPT_CONF")
            .context("couldn't get INTERCEPT_CONF map")?;
        Array::<_, ActionWrapper>::try_from(map)
            .context("Cannot cast INTERCEPT_CONF to Array")?
    };

    info!("Connecting to {}...", mitmproxy_addr.display());
    let ipc = UnixDatagram::bind(&redirector_addr)
        .with_context(|| format!("failed to bind to {}", redirector_addr.display()))?;
    ipc.connect(&mitmproxy_addr)
        .with_context(|| format!("failed to connect to {}", mitmproxy_addr.display()))?;
    fs::set_permissions(&mitmproxy_addr, Permissions::from_mode(0o777))?;
    fs::set_permissions(&redirector_addr, Permissions::from_mode(0o777))?;
    println!("{}", redirector_addr.to_string_lossy());

    let mut ipc_buf = BytesMut::with_capacity(IPC_BUF_SIZE);
    let mut dev_buf = BytesMut::with_capacity(IPC_BUF_SIZE);

    loop {
        select! {
            r = ipc.recv_buf(&mut ipc_buf) => {
                match r {
                    Ok(len) if len > 0 => {
                        debug!("Received IPC message: {len} {:?}", &ipc_buf[..len]);

                        let Ok(FromProxy { message: Some(message)}) = FromProxy::decode(&mut ipc_buf) else {
                            return Err(anyhow!("Received invalid IPC message: {:?}", &ipc_buf[..len]));
                        };
                        assert_eq!(ipc_buf.len(), 0);

                        match message {
                            from_proxy::Message::Packet(packet) => {
                                debug!("Received Packet: {packet:?}");
                                device.send(&packet.data).await.context("failed to send packet")?;
                            }
                            from_proxy::Message::InterceptConf(conf) => {
                                info!("Received InterceptConf: {conf:?}");
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
                        std::process::exit(0);
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
                let encoded = ipc_buf.split();

                info!("Sending packet to proxy: {} {:?}", encoded.len(), &encoded);
                ipc.send(&encoded).await?;
            },
        }
    }
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
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
}