use anyhow::Result;
//use objc::runtime::AnyClass;
use sysinfo::{PidExt, ProcessRefreshKind, System, SystemExt};
use crate::processes::ProcessList;

//use cocoa::appkit::NSRunningApplication;

// use cacao::foundation::{id, nil, NSString,  NSURL, BOOL};
// use objc::{sel, sel_impl, msg_send, class};
use std::ptr;
use std::os::raw::{c_char, c_int};
use libc::{proc_pidpath, proc_name,PROC_PIDPATHINFO_MAXSIZE, c_void, PROC_PIDTBSDINFO, proc_pidinfo, proc_bsdinfo};
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
        // dbg!(proc);
        //dbg!(AnyClass::classes_count());
        //let int_value: pid_t = proc.0.as_u32() as i32;
        // let cls = NSRunningApplication::class();
        //let nsrunning = class!(NSRunningApplication);
        unsafe {
                // let mut path_buffer: [c_char; PROC_PIDPATHINFO_MAXSIZE as usize] = [0; PROC_PIDPATHINFO_MAXSIZE as usize];
                // let mut name_buffer: [c_char; 256] = [0; 256];
                const PROC_PIDTBSDINFO_SIZE:usize = std::mem::size_of::<proc_bsdinfo>();
                let mut bsd_info: [c_char;  PROC_PIDTBSDINFO_SIZE] = [0; PROC_PIDTBSDINFO_SIZE];

                let ret = proc_pidinfo(proc.0.as_u32() as i32, PROC_PIDTBSDINFO, 0, bsd_info.as_mut_ptr() as *mut c_void, PROC_PIDTBSDINFO_SIZE as i32);
                let bsd_info_struct: proc_bsdinfo = std::mem::transmute(bsd_info);
                if ret as usize == PROC_PIDTBSDINFO_SIZE {
                    println!("Process ID: {}", bsd_info_struct.pbi_pid);
                    println!("Process Name: {:?}", std::ffi::CStr::from_ptr(bsd_info_struct.pbi_comm.as_ptr()));
                    println!("Process status: {:?}", bsd_info_struct.pbi_status);
                } else {
                    println!("VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
                    println!("Error for pid {}", proc.0.as_u32());
                    println!("Process ID: {}", bsd_info_struct.pbi_pid);
                    println!("Process Name: {:?}", std::ffi::CStr::from_ptr(bsd_info_struct.pbi_comm.as_ptr()));
                    println!("Process status: {:?}", bsd_info_struct.pbi_status);
                    println!("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
                }

                // proc_pidpath(proc.0.as_u32() as i32, path_buffer.as_mut_ptr() as *mut c_void, PROC_PIDPATHINFO_MAXSIZE as u32);
                // proc_name(proc.0.as_u32() as i32, name_buffer.as_mut_ptr() as *mut c_void, size_of_val);

                // let path_str = std::ffi::CStr::from_ptr(path_buffer.as_ptr()).to_str().unwrap();
                // let name_str = std::ffi::CStr::from_ptr(name_buffer.as_ptr()).to_str().unwrap();

                // println!("Path: {}\nName: {}", path_str, name_str);
                //let proces_info = class!(NSPRocessInfo);
                //let app: id = msg_send![app_class, currentApplication];
                // let app: id = msg_send![app_class, runningApplicationWithProcessIdentifier: proc.0.as_u32() as i32];
                // let localized_name: id = msg_send![app, localizedName];
                // if localized_name != nil {
                //     let localized_name = NSString::retain(localized_name).to_string();
                //     dbg!(localized_name);
                // }
                //
                // let bundle_identifier: id = msg_send![app, bundleIdentifier];
                // if bundle_identifier != nil {
                //     let bundle_identifier = NSString::retain(bundle_identifier).to_string();
                //     // dbg!(bundle_identifier);
                //
                //     let hidden: BOOL = msg_send![app, isHidden];
                //     // dbg!(hidden);
                // }
                //
                // let executable: id = msg_send![app, executableURL];
                // if executable != nil {
                //     let executable = NSURL::retain(executable).pathbuf();
                //     // dbg!(executable);
                // }

        }
        // unsafe{
            //let current_app = NSRunningApplication::runningApplicationWithProcessIdentifier(nil, int_value);
            //let app_name: id = msg_send![current_app, localizedName];
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
        // };

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
