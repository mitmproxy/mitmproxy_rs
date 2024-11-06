#[cfg(target_os = "macos")]
use security_framework::{
    item::{ItemClass, ItemSearchOptions, Reference, SearchResult},
    trust_settings::{Domain, TrustSettings},
};

#[cfg(target_os = "macos")]
fn main() {
    if let SearchResult::Ref(Reference::Certificate(cert)) = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .label("mitmproxy")
        .search()
        .unwrap()
        .first()
        .unwrap()
    {
        TrustSettings::new(Domain::Admin)
            .set_trust_settings_always(cert)
            .unwrap();
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("The macOS certificate truster works on macOS only.");
}
