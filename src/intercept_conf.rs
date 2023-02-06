use anyhow::bail;
#[cfg(windows)]
use bincode::{Decode, Encode};
use std::collections::HashSet;

pub type PID = u32;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: PID,
    pub process_name: Option<String>,
}

#[cfg_attr(windows, derive(Decode, Encode))]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct InterceptConf {
    pids: HashSet<PID>,
    process_names: Vec<String>,
    /// if true, matching items are the ones which are not intercepted.
    invert: bool,
}

impl TryFrom<&str> for InterceptConf {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut val = value.trim();
        if val.is_empty() {
            return Ok(InterceptConf::new(vec![], vec![], false));
        }
        let invert = if val.starts_with('!') {
            val = &val[1..];
            true
        } else {
            false
        };

        let mut pids = vec![];
        let mut procs = vec![];
        for part in val.split(',') {
            let part = part.trim();
            if part.is_empty() {
                bail!("invalid intercept spec: {}", value);
            }
            match part.parse::<PID>() {
                Ok(pid) => pids.push(pid),
                Err(_) => procs.push(part.to_string()),
            }
        }
        Ok(InterceptConf::new(pids, procs, invert))
    }
}

impl InterceptConf {
    pub fn new(pids: Vec<PID>, process_names: Vec<String>, invert: bool) -> Self {
        let pids = HashSet::from_iter(pids.into_iter());
        if invert {
            assert!(!pids.is_empty() || !process_names.is_empty());
        }
        Self {
            pids,
            process_names,
            invert,
        }
    }

    pub fn should_intercept(&self, process_info: &ProcessInfo) -> bool {
        self.invert ^ {
            if self.pids.contains(&process_info.pid) {
                true
            } else if let Some(name) = &process_info.process_name {
                self.process_names.iter().any(|n| name.contains(n))
            } else {
                false
            }
        }
    }

    pub fn description(&self) -> String {
        if self.pids.is_empty() && self.process_names.is_empty() {
            return "Intercept nothing.".to_string();
        }
        let mut parts = vec![];
        if !self.pids.is_empty() {
            parts.push(format!("pids: {:?}", self.pids));
        }
        if !self.process_names.is_empty() {
            parts.push(format!("process names: {:?}", self.process_names));
        }
        let start = if self.invert {
            "Intercepting all packets but those from "
        } else {
            "Intercepting packets from "
        };
        format!("{}{}", start, parts.join(" or "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intercept_conf() {
        let a = ProcessInfo {
            pid: 1,
            process_name: Some("a".into()),
        };
        let b = ProcessInfo {
            pid: 2242,
            process_name: Some("mitmproxy".into()),
        };

        let conf = InterceptConf::try_from("1,2,3").unwrap();
        assert_eq!(conf.pids, vec![1, 2, 3].into_iter().collect());
        assert!(conf.process_names.is_empty());
        assert!(!conf.invert);
        assert!(conf.should_intercept(&a));
        assert!(!conf.should_intercept(&b));

        let conf = InterceptConf::try_from("").unwrap();
        assert!(conf.pids.is_empty());
        assert!(conf.process_names.is_empty());
        assert!(!conf.invert);
        assert!(!conf.should_intercept(&a));
        assert!(!conf.should_intercept(&b));

        let conf = InterceptConf::try_from("!2242").unwrap();
        assert_eq!(conf.pids, vec![2242].into_iter().collect());
        assert!(conf.process_names.is_empty());
        assert!(conf.invert);
        assert!(conf.should_intercept(&a));
        assert!(!conf.should_intercept(&b));

        assert!(InterceptConf::try_from(",,").is_err());
    }
}
