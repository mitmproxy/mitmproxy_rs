use anyhow::{anyhow, Result};
use security_framework::{
    certificate::SecCertificate,
    item::{
        add_item, AddRef, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Reference,
        SearchResult,
    },
};
use tokio::process::Command;

pub fn add_cert(der: Vec<u8>, path: &str) -> Result<()> {
    let cert = SecCertificate::from_der(&der)?;
    let add_ref = AddRef::Certificate(cert);
    let add_option = ItemAddOptions::new(ItemAddValue::Ref(add_ref))
        .set_label("mitmproxy")
        .to_dictionary();

    let search_result = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .label("mitmproxy")
        .search()
        .map_err(|e| anyhow!(e))?;

    if let Some(SearchResult::Ref(Reference::Certificate(cert))) = search_result.first() {
        cert.delete()?;
    }

    add_item(add_option)?;

    Command::new("open")
        .arg(path)
        .spawn()
        .map_err(|e| anyhow!(e))?;
    Ok(())
}

pub fn remove_cert() -> Result<()> {
    if let SearchResult::Ref(Reference::Certificate(cert)) = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .label("mitmproxy")
        .search()
        .map_err(|e| anyhow!(e))?
        .first()
        .ok_or_else(|| anyhow!("Certificate not found"))?
    {
        cert.delete().map_err(|e| anyhow!(e))?;
    };
    Ok(())
}
