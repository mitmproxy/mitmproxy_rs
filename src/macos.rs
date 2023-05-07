use security_framework::{
    base::Result,
    certificate::SecCertificate,
    item::{add_item, AddRef, ItemAddOptions, ItemAddValue},
};
use pem_parser;
use dirs;
use std::fs;

pub fn load_cert() -> Result<()> {
    let home = dirs::home_dir().unwrap();
    // Load the mitmproxy CA certificate into a buffer
    let cert_der = pem_parser::pem_to_der(fs::read_to_string(format!("{}/.mitmproxy/mitmproxy-ca-cert.pem", home.to_str().unwrap())).unwrap().as_str());
    // Create a `SecCertificate` from the certificate buffer
    let cert = SecCertificate::from_der(&cert_der)?;

    let add_ref = AddRef::Certificate(cert.clone());
    let add_option = ItemAddOptions::new(ItemAddValue::Ref(add_ref)).to_dictionary();

    add_item(add_option)
}
