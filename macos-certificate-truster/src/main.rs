use apple_security::{
    item::{ItemClass, ItemSearchOptions, Reference, SearchResult},
    trust_settings::{Domain, TrustSettings},
};

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
