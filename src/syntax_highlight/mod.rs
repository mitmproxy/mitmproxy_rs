mod common;
mod xml;
mod yaml;

pub type Chunk = (&'static str, String);

pub enum Language {
    Xml,
    Yaml,
}

impl Language {
    pub fn highlight(&self, input: &[u8]) -> anyhow::Result<Vec<Chunk>> {
        match self {
            Language::Yaml => yaml::highlight_yaml(input),
            Language::Xml => xml::highlight_xml(input),
        }
    }
    
    pub fn all_tags(&self) -> &'static [&'static str] {
        match self {
            Language::Xml => xml::XML_TAGS,
            Language::Yaml => yaml::YAML_TAGS,
        }
    }
}
