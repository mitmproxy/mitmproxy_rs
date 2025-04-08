use crate::{Metadata, Prettify, Protobuf, Reencode};
use mitmproxy_highlight::Language;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_yaml::Value;

pub struct GRPC;

impl Prettify for GRPC {
    fn name(&self) -> &'static str {
        "gRPC"
    }

    fn syntax_highlight(&self) -> Language {
        Language::Yaml
    }

    fn prettify(&self, mut data: &[u8], metadata: &dyn Metadata) -> Result<String> {
        let mut protos = vec![];

        while !data.is_empty() {
            let compressed = match data[0] {
                0 => false,
                1 => true,
                _ => bail!("invalid gRPC: first byte is not a boolean"),
            };
            let len = match data.get(1..5) {
                Some(x) => u32::from_be_bytes(x.try_into()?) as usize,
                _ => bail!("invalid gRPC: first byte is not a boolean"),
            };
            let Some(proto) = data.get(5..5 + len) else {
                bail!("Invald gRPC: not enough data")
            };
            if compressed {
                todo!();
            }
            protos.push(proto);
            data = &data[5 + len..];
        }

        let prettified = protos
            .into_iter()
            .map(|proto| Protobuf.prettify(proto, metadata))
            .collect::<Result<Vec<String>>>()?;
        Ok(prettified.join("\n---\n\n"))
    }

    fn render_priority(&self, _data: &[u8], metadata: &dyn Metadata) -> f64 {
        let Some(ct) = metadata.content_type() else {
            return 0.0;
        };
        match ct.as_str() {
            "application/grpc" => 2.0,
            "application/grpc+proto" => 2.0,
            "application/prpc" => 2.0,
            _ => 0.0,
        }
    }
}

impl Reencode for GRPC {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>> {
        let mut ret = vec![];
        for document in serde_yaml::Deserializer::from_str(data) {
            let value = Value::deserialize(document).context("Invalid YAML")?;
            let proto = super::protobuf::reencode::reencode_yaml(value, metadata)?;
            ret.push(0); // compressed
            ret.extend(u32::to_be_bytes(proto.len() as u32));
            ret.extend(proto);
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_grpc() {
        // FIXME
    }
}
