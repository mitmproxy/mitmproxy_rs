use std::ops::Deref;
use anyhow::Context;
use aya::EbpfLoader;
use std::io::Cursor;
use aya::Btf;
use aya::programs::{links::CgroupAttachMode, CgroupSock};
use log::{debug, warn, info};
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::signal;
use mitmproxy::packet_sources::tun::create_tun_device;
use tun::AbstractDevice;
use prost::Message;
use mitmproxy::ipc::PacketWithMeta;
use mitmproxy::ipc::FromProxy;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    )
        //.format_target(false)
        .format_timestamp(None)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let pipe_name = args
        .get(1)
        .map(|x| x.as_str())
        .with_context(|| format!("usage: {} <pipe>", args[0]))?;

    info!("Connecting to {pipe_name}...");
    let mut stream = UnixStream::connect(pipe_name)
        .await
        .with_context(|| format!("failed to connect to {pipe_name}"))?;

    info!("Creating tun device...");
    let (mut device, name) = create_tun_device(None)?;
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


    let mut buf = vec![0; device.mtu()? as usize + 1024];
    let r = device.recv(buf.as_mut_slice()).await;
    info!("r={r:?}");


    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
