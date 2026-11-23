#![no_std]
#![no_main]

use aya_ebpf::EbpfContext;
use aya_ebpf::macros::{cgroup_sock, map};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::SockContext;
use aya_log_ebpf::debug;
use mitmproxy_linux_ebpf_common::{Action, INTERCEPT_CONF_LEN, INTERCEPT_TGID_LEN};

#[unsafe(no_mangle)]
static INTERFACE_ID: u32 = 0;

#[map]
static INTERCEPT_CONF: Array<Action> = Array::with_max_entries(INTERCEPT_CONF_LEN, 0);

/// tgids of processes matching process name include patterns, resolved in userspace.
#[map]
static INTERCEPT_TGID_INCLUDE: HashMap<u32, u8> = HashMap::with_max_entries(INTERCEPT_TGID_LEN, 0);

/// tgids of processes matching process name exclude patterns, resolved in userspace.
#[map]
static INTERCEPT_TGID_EXCLUDE: HashMap<u32, u8> = HashMap::with_max_entries(INTERCEPT_TGID_LEN, 0);

#[cgroup_sock(sock_create)]
pub fn cgroup_sock_create(ctx: SockContext) -> i32 {
    if should_intercept(&ctx) {
        debug!(&ctx, "intercepting in sock_create");
        let interface_id = unsafe { core::ptr::read_volatile(&INTERFACE_ID) };
        unsafe {
            (*ctx.sock).bound_dev_if = interface_id;
        }
    }
    1
}

pub fn should_intercept(ctx: &SockContext) -> bool {
    let pid = ctx.tgid();

    // Pid patterns can be matched here. Process names cannot: the kernel only exposes the
    // name of the thread that creates the socket, which differs from the process name for
    // most multithreaded applications. Name patterns are matched against tgid sets that
    // userspace resolves by scanning /proc.
    let mut intercept = matches!(INTERCEPT_CONF.get(0), Some(Action::Exclude(_)));
    for i in 0..INTERCEPT_CONF_LEN {
        match INTERCEPT_CONF.get(i) {
            Some(Action::Include(pattern_pid)) => {
                intercept = intercept || pid == *pattern_pid;
            }
            Some(Action::Exclude(pattern_pid)) => {
                intercept = intercept && pid != *pattern_pid;
            }
            Some(Action::IncludeName) => {
                intercept = intercept || INTERCEPT_TGID_INCLUDE.get_ptr(&pid).is_some();
            }
            Some(Action::ExcludeName) => {
                intercept = intercept && INTERCEPT_TGID_EXCLUDE.get_ptr(&pid).is_none();
            }
            _ => {
                break;
            }
        }
    }
    intercept
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
