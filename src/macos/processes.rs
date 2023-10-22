use anyhow::Result;
use objc2::runtime::NSObject;
use objc2::runtime::NSObjectProtocol;
use objc2::ffi::id;
use objc2::msg_send;
use objc2::class;
use sysinfo::{PidExt, ProcessRefreshKind, System, SystemExt};
use crate::processes::ProcessList;
use objc2::{extern_class, msg_send_id, mutability, ClassType};
use icrate::AppKit::NSRunningApplication;
// extern_class!(
//     #[derive(Debug, PartialEq, Eq, Hash)]
//     #[cfg(feature = "AppKit_NSRunningApplication")]
//     pub struct NSRunningApplication;
//
//     #[cfg(feature = "AppKit_NSRunningApplication")]
//     unsafe impl ClassType for NSRunningApplication {
//         type Super = NSObject;
//         type Mutability = InteriorMutable;
//     }
// );
// extern_class!(
//     /// An example description.
//     #[derive(PartialEq, Eq, Hash)] // Uses the superclass' implementation
//     // Specify the class and struct name to be used
//     pub struct NSRunningApplication;
//
//     // Specify the superclass, in this case `NSObject`
//     unsafe impl ClassType for NSRunningApplication {
//         type Super = NSObject;
//         type Mutability = mutability::InteriorMutable;
//         // Optionally, specify the name of the class, if it differs from
//         // the struct name.
//         // const NAME: &'static str = "NSFormatter";
//     }
// );
// unsafe impl NSObjectProtocol for NSRunningApplication {}
    // pub executable: PathBuf,
    // pub display_name: String,
    // pub is_visible: bool,
    // pub is_system: bool,

pub fn active_executables() -> Result<ProcessList> {
    dbg!("active_executables");

    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for proc in sys.processes() {
        dbg!(proc);

        let int_value = proc.0.as_u32();
        // let cls = NSRunningApplication::class();
        unsafe{
            let p: i32 = msg_send![
                class!(NSRunningApplication),
                runningApplicationWithProcessIdentifier: int_value
            ];
        dbg!(p);
        };

    }

    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_list() {
        let lst = active_executables().unwrap();
        assert!(!lst.is_empty());

        for proc in &lst {
            dbg!(proc);
        }
        dbg!(lst.len());
    }
}
