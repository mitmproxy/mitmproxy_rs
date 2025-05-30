use anyhow::bail;
use std::str::FromStr;

pub mod common;
mod xml;
mod yaml;

pub type Chunk = (Tag, String);

pub enum Language {
    Xml,
    Yaml,
    Error,
    None,
}

impl Language {
    pub fn highlight(&self, input: &[u8]) -> anyhow::Result<Vec<Chunk>> {
        match self {
            Language::Yaml => yaml::highlight_yaml(input),
            Language::Xml => xml::highlight_xml(input),
            Language::None => Ok(vec![(
                Tag::Text,
                String::from_utf8_lossy(input).to_string(),
            )]),
            Language::Error => Ok(vec![(
                Tag::Error,
                String::from_utf8_lossy(input).to_string(),
            )]),
        }
    }

    pub const VALUES: [Self; 4] = [Self::Xml, Self::Yaml, Self::Error, Self::None];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Xml => "xml",
            Self::Yaml => "yaml",
            Self::Error => "error",
            Self::None => "none",
        }
    }
}

impl FromStr for Language {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "xml" => Language::Xml,
            "yaml" => Language::Yaml,
            "none" => Language::None,
            "error" => Language::Error,
            other => bail!("Unsupported language: {other}"),
        })
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Tag {
    Text,    // Text that shouldn't be emphasized.
    Name,    // A tag, such as an HTML tag or a YAML key.
    String,  // A string value.
    Number,  // A number value.
    Boolean, // A boolean value.
    Comment, // A comment.
    Error,   // An error value.
}

impl Tag {
    pub const VALUES: [Self; 7] = [
        Self::Text,
        Self::Name,
        Self::String,
        Self::Number,
        Self::Boolean,
        Self::Comment,
        Self::Error,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Tag::Text => "",
            Tag::Name => "name",
            Tag::String => "string",
            Tag::Number => "number",
            Tag::Boolean => "boolean",
            Tag::Comment => "comment",
            Tag::Error => "error",
        }
    }
}
