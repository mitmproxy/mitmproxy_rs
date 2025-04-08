mod grpc;
mod hex_dump;
mod hex_stream;
mod msgpack;
mod protobuf;

pub use grpc::GRPC;
pub use hex_dump::HexDump;
pub use hex_stream::HexStream;
pub use msgpack::MsgPack;
pub use protobuf::Protobuf;

use anyhow::Result;
use mitmproxy_highlight::Language;

pub trait Metadata {
    fn content_type(&self) -> Option<&str>;
}

pub trait Prettify: Send + Sync {
    fn name(&self) -> &str;

    fn instance_name(&self) -> String {
        self.name().to_lowercase().replace(" ", "_")
    }

    fn syntax_highlight(&self) -> Language {
        Language::None
    }

    fn prettify(&self, data: &[u8], metadata: &dyn Metadata) -> Result<String>;

    #[allow(unused_variables)]
    fn render_priority(&self, data: &[u8], metadata: &dyn Metadata) -> f64 {
        0.0
    }
}

pub trait Reencode: Send + Sync {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>>;
}

#[derive(Default)]
pub struct TestMetadata {
    pub content_type: Option<String>,
}

impl Metadata for TestMetadata {
    fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
}
