use std::fs;
use std::fs::Permissions;
use anyhow::Context;
use anyhow::anyhow;
use aya::EbpfLoader;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use aya::Btf;
use aya::programs::{links::CgroupAttachMode, CgroupSock};
use log::{debug, warn, info};
use tokio::net::UnixDatagram;
use tokio::select;
use mitmproxy::packet_sources::tun::create_tun_device;
use tun::AbstractDevice;
use prost::Message;
use mitmproxy::ipc::{PacketWithMeta, TunnelInfo, from_proxy};
use mitmproxy::ipc::FromProxy;
use mitmproxy::packet_sources::IPC_BUF_SIZE;
use mitmproxy_linux_ebpf_common::{Action, Pattern};

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

    info!("Creating tun device...");
    let (device, name) = create_tun_device(None)?;
    let device_index = device.tun_index().context("failed to get tun device index")? as u32;
    info!("Tun device created: {name} (id={device_index})");


    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.

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

    let prog: &mut CgroupSock = ebpf.program_mut("cgroup_sock_create").unwrap().try_into()?;
    // root cgroup to get all events.
    let cgroup = std::fs::File::open("/sys/fs/cgroup/")?;
    prog.load()?;
    prog.attach(&cgroup, CgroupAttachMode::Single)?;
    info!("Attached!");

    let mut config = aya::maps::Array::<_, Action>::try_from(ebpf.map_mut("INTERCEPT_CONF").unwrap())?;
    config.set(
        0,
        Action::Include(Pattern::from("nc")),
        0,
    )?;

    let pipe_name = pipe_dir.join("mitmproxy");
    info!("Connecting to {}...", pipe_name.display());
    let datagram_path = pipe_dir.join("redirector");
    let ipc = UnixDatagram::bind(&datagram_path)
        .with_context(|| format!("failed to bind to {}", datagram_path.display()))?;
    ipc.connect(&pipe_name)
        .with_context(|| format!("failed to connect to {}", pipe_name.display()))?;
    fs::set_permissions(&pipe_name, Permissions::from_mode(0o777))?;
    fs::set_permissions(&datagram_path, Permissions::from_mode(0o777))?;
    println!("{}", datagram_path.to_string_lossy());

    let mut ipc_buf = [0u8; IPC_BUF_SIZE];
    let mut dev_buf = [0u8; IPC_BUF_SIZE];

    loop {
        select! {
            r = ipc.recv(&mut ipc_buf) => {
                match r {
                    Ok(len) if len > 0 => {

                        let mut cursor = Cursor::new(&ipc_buf[..len]);

                        info!("Received IPC message: {len} {:?}", &ipc_buf[..len]);


                        let Ok(FromProxy { message: Some(message)}) = FromProxy::decode(&mut cursor) else {
                            return Err(anyhow!("Received invalid IPC message: {:?}", &ipc_buf[..len]));
                        };
                        assert_eq!(cursor.position(), len as u64);

                        match message {
                            from_proxy::Message::Packet(packet) => {
                                info!("Received Packet: {packet:?}");
                                device.send(&packet.data).await?;
                            }
                            from_proxy::Message::InterceptConf(conf) => {
                                info!("Received InterceptConf: {conf:?}");
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
            r = device.recv(dev_buf.as_mut_slice()) => {
                let len = r.context("TUN read() failed")?;

                // Unnecessary copying, oh well...
                let packet = PacketWithMeta {
                    data: dev_buf[..len].to_vec(),
                    // FIXME
                    tunnel_info: Some(TunnelInfo {
                        pid: 0,
                        process_name: None,
                    }),
                };

                packet.encode(&mut dev_buf.as_mut_slice())?;
                let len = packet.encoded_len();

                info!("Sending packet: {} {:?}", len, &dev_buf[..len]);

                ipc.send(&dev_buf[..len]).await?;
            },
        }
    }
}
