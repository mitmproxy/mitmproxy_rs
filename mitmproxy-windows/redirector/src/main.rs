#[cfg(windows)]
include!("main2.rs");

#[cfg(not(windows))]
pub fn main() {
    panic!("The Windows redirector works on Windows only.");
}
