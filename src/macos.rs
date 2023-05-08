use security_framework::{
    base::Result,
    certificate::SecCertificate,
    item::{add_item, AddRef, ItemAddOptions, ItemAddValue},
};

pub fn add_cert(der: Vec<u8>) -> Result<()> {
    let cert = SecCertificate::from_der(&der)?;
    let add_ref = AddRef::Certificate(cert.clone());
    let add_option = ItemAddOptions::new(ItemAddValue::Ref(add_ref)).to_dictionary();
    add_item(add_option)
}
