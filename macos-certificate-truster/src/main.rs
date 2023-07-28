use security_framework::{trust_settings::{TrustSettings, Domain}, item::{
     ItemClass, ItemSearchOptions, Reference,
    SearchResult,
}};
use embed_plist;

fn main() {
    embed_plist::embed_launchd_plist!("../macos-certificate-truster.app/Contents/Info.plist");
    if let SearchResult::Ref(Reference::Certificate(cert)) = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .label("mitmproxy")
        .search()
        .unwrap()
        .first()
        .unwrap()
    {
        TrustSettings::new(Domain::Admin).set_trust_settings_always(&cert).unwrap();
    }
}
