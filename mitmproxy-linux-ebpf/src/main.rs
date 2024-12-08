#![no_std]
#![no_main]

use aya_ebpf::cty::c_long;
use aya_ebpf::macros::{cgroup_sock, map};
use aya_ebpf::programs::SockContext;
use aya_ebpf::{EbpfContext, TASK_COMM_LEN};
use aya_ebpf::maps::Array;
use aya_log_ebpf::info;
use mitmproxy_linux_ebpf_common::Action;

#[no_mangle]
static INTERFACE_ID: u32 = 0;

const INTERCEPT_CONF_LEN: u32 = 20;

#[map]
static INTERCEPT_CONF: Array<Action> = Array::with_max_entries(INTERCEPT_CONF_LEN, 0);

pub fn should_intercept(ctx: &SockContext) -> bool {
    let command = ctx.command().ok();
    let pid = ctx.pid();

    let mut intercept = matches!(INTERCEPT_CONF.get(0), Some(Action::Exclude(_)));
    for i in 0..INTERCEPT_CONF_LEN {
        match INTERCEPT_CONF.get(i) {
            Some(Action::Include(pattern)) => {
                intercept = intercept || pattern.matches(command.as_ref(), pid);
            }
            Some(Action::Exclude(pattern)) => {
                intercept = intercept && !pattern.matches(command.as_ref(), pid);
            }
            _ => {
                break;
            }
        }
    }
    intercept
}

#[cgroup_sock(sock_create)]
pub fn cgroup_sock_create(ctx: SockContext) -> i32 {
    if should_intercept(&ctx) {
        info!(&ctx, "sock_create from nc");
        let interface_id = unsafe {
            core::ptr::read_volatile(&INTERFACE_ID)
        };
        unsafe {
            (*ctx.sock).bound_dev_if = interface_id;  // Replace with interface id from `ip link show`
        }
    }
    1
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
