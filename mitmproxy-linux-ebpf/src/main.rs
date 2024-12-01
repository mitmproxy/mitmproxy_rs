#![no_std]
#![no_main]

use aya_ebpf::{EbpfContext, TASK_COMM_LEN};
use aya_ebpf::cty::c_long;
use aya_ebpf::macros::cgroup_sock;
use aya_ebpf::programs::SockContext;
use aya_log_ebpf::info;

pub fn command_to_str(command: &[u8; 16]) -> &str {
    let len = command.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(command.len());
    unsafe { core::str::from_utf8_unchecked(&command[..len]) }
}

pub fn is_nc(command: Result<[u8; TASK_COMM_LEN], c_long>) -> bool {
    let c = command.unwrap_or_default();
    let cmd = command_to_str(&c);
    cmd == "nc"
}

#[cgroup_sock(sock_create)]
pub fn cgroup_sock_create(ctx: SockContext) -> i32 {
    if is_nc(ctx.command()) {
        info!(&ctx, "sock_create from nc");
    }
    /*
    unsafe {
        // XXX: something is off here.
        // bpf_printk!(b"sock_create! %u", (*ctx.sock).src_port);
        // info!(&ctx, "sock_create {:x} {:x}", (*ctx.sock).src_port, (*ctx.sock).dst_ip6[0]);
    }
    if is_nc(ctx.command()) {


        info!(&ctx, "sock_create {}", unsafe { (*ctx.sock).dst_port });
        /*unsafe {
            (*ctx.sock).bound_dev_if = 143;  // Replace with interface id from `ip link show`
        }*/
    }
    */
    1
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
