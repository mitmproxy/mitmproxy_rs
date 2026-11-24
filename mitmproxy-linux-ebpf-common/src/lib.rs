#![no_std]

type Pid = u32;

pub const INTERCEPT_CONF_LEN: u32 = 20;

/// Maximum number of tgids per map that we resolve for process name patterns.
pub const INTERCEPT_TGID_LEN: u32 = 16384;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum Action {
    None,
    Include(Pid),
    Exclude(Pid),
    /// Matches processes by name. Userspace resolves name patterns to tgid sets and keeps
    /// them in the INTERCEPT_TGID_INCLUDE eBPF map, since the eBPF program itself can only
    /// see the name of the thread that creates a socket.
    IncludeName,
    /// Excludes processes by name, resolved like [`Action::IncludeName`].
    ExcludeName,
}

impl From<&str> for Action {
    fn from(value: &str) -> Self {
        let value = value.trim();
        match value.strip_prefix('!') {
            Some(pid) => pid
                .parse()
                .map(Action::Exclude)
                .unwrap_or(Action::ExcludeName),
            None => value
                .parse()
                .map(Action::Include)
                .unwrap_or(Action::IncludeName),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::Action;

    #[test]
    fn test_action_from_str() {
        assert_eq!(Action::from("42"), Action::Include(42));
        assert_eq!(Action::from("!42"), Action::Exclude(42));
        assert_eq!(Action::from(" 42 "), Action::Include(42));
        assert_eq!(Action::from("firefox"), Action::IncludeName);
        assert_eq!(Action::from("!firefox"), Action::ExcludeName);
    }
}
