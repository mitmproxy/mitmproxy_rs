use anyhow::Result;
//use objc::runtime::AnyClass;
use sysinfo::{PidExt, ProcessRefreshKind, System, SystemExt};
use crate::processes::ProcessList;

use cocoa::appkit::NSRunningApplication;

use cocoa::{
    base::{id, nil},
};
use objc::{sel, msg_send, class};

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
        //dbg!(AnyClass::classes_count());
        pub type pid_t = i32;
        let int_value: pid_t = proc.0.as_u32() as i32;
        // let cls = NSRunningApplication::class();
        //let nsrunning = class!(NSRunningApplication);
        unsafe{
            //let current_app = NSRunningApplication::runningApplicationWithProcessIdentifier(nil, int_value);
            let app_class = class!(NSRunningApplication);
            let app: id = msg_send![app_class, currentApplication];
            let app_name: id = msg_send![app, localizedName];
            //let app_name: id = msg_send![current_app, localizedName];
            dbg!(app_name);
            //current_app.activateWithOptions_(NSApplicationActivateIgnoringOtherApps);
            // let superclass = class!(NSObject);
            // let mut decl = objc2::declare::ClassBuilder::new("NSRunningApplication", superclass).unwrap();
            // decl.register();
            //dbg!(AnyClass::get("NSRunningApplication"));
            // let app_class = class!(NSRunningApplication);
            // let app_with_process_id: *mut Object = msg_send![
            //     app_class,
            //     runningApplicationWithProcessIdentifier: process_id as i64
            // ];
            //let app_class = class!(NSRunningApplication);
            //let p: i32 = msg_send![ app_class, runningApplicationWithProcessIdentifier: int_value ];
            //dbg!(p);
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
