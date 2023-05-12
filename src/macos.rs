use security_framework::{
    base::Result,
    certificate::SecCertificate,
    item::{
        add_item, AddRef, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Reference,
        SearchResult,
    },
};

pub fn add_trusted_cert(der: Vec<u8>) -> Result<()> {
    let cert = SecCertificate::from_der(&der)?;
    let add_ref = AddRef::Certificate(cert.clone());
    let add_option = ItemAddOptions::new(ItemAddValue::Ref(add_ref))
        .set_label("mitmproxy")
        .to_dictionary();

    ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .label("mitmproxy")
        .search()
        .and_then(|_| Ok(()))
        .unwrap_or_else(|_| add_item(add_option).unwrap());

    if let Err(err) = std::process::Command::new("open")
        .arg("../macos-trust-cert.app")
        .spawn()
        .unwrap()
        .wait()
    {
        panic!("Error during trust process: {:?}", err);
    }
    Ok(())
}

pub fn delete_cert() -> Result<()> {
    if let SearchResult::Ref(Reference::Certificate(cert)) = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .label("mitmproxy")
        .search()
        .unwrap()
        .first()
        .unwrap()
    {
        cert.delete().unwrap();
    };
    Ok(())
}
