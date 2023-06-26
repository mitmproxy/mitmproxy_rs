use anyhow::{anyhow, Result};
use security_framework::{
    certificate::SecCertificate,
    item::{
        add_item, AddRef, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Reference,
        SearchResult,
    },
};
use tokio::process::Command;


pub mod raw_packet {
    include!(concat!(env!("OUT_DIR"), "/pipe_rs.raw_packet.rs"));
}

pub fn serialize_packet(raw_packet: &raw_packet::Packet) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(raw_packet.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    raw_packet.encode(&mut buf).unwrap();
    buf
}

pub fn deserialize_packet(buf: &[u8]) -> Result<raw_packet::Packet, prost::DecodeError> {
    raw_packet::Packet::decode(&mut Cursor::new(buf))
}

pub fn copy_dir(src: &Path, dst: &Path) -> io::Result<()> {
    for entry in src.read_dir()? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_dir(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

pub fn add_trusted_cert(der: Vec<u8>) -> Result<()> {
    let cert = SecCertificate::from_der(&der)?;
    let add_ref = AddRef::Certificate(cert.clone());
    let add_option = ItemAddOptions::new(ItemAddValue::Ref(add_ref))
        .set_label("mitmproxy")
        .to_dictionary();

    let search_result = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .label("mitmproxy")
        .search()
        .map_err(|e| anyhow!(e))?;

    if let Some(search_result) = search_result.first() {
        if let SearchResult::Ref(Reference::Certificate(cert)) = search_result {
            cert.delete()?;
        }
    }

    add_item(add_option)?;

    Command::new("open")
        .arg("../macos-add-trusted-cert/macos-add-trusted-cert.app")
        .spawn()
        .map_err(|e| anyhow!(e))?;
    Ok(())
}

pub fn remove_trusted_cert() -> Result<()> {
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
