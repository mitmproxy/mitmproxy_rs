mod hex_dump;
mod hex_stream;
mod msgpack;
mod protobuf;

use anyhow::Result;

pub use hex_dump::HexDump;
pub use hex_stream::HexStream;
pub use msgpack::MsgPack;
pub use protobuf::Protobuf;

pub trait Prettify: Send + Sync {
    fn name(&self) -> &str;

    fn instance_name(&self) -> String {
        self.name().to_lowercase().replace(" ", "_")
    }

    fn prettify(&self, data: &[u8]) -> Result<String>;
}

pub trait Reencode: Send + Sync {
    fn reencode(&self, data: &str) -> Result<Vec<u8>>;
}
