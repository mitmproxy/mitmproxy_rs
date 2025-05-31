use anyhow::bail;
use std::str::FromStr;

pub mod common;
mod css;
mod javascript;
mod xml;
mod yaml;

pub type Chunk = (Tag, String);

pub enum Language {
    Css,
    JavaScript,
    Xml,
    Yaml,
    None,
    Error,
}

impl Language {
    pub fn highlight(&self, input: &[u8]) -> anyhow::Result<Vec<Chunk>> {
        match self {
            Language::Css => css::highlight(input),
            Language::JavaScript => javascript::highlight(input),
            Language::Xml => xml::highlight(input),
            Language::Yaml => yaml::highlight(input),
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

    pub const VALUES: [Self; 6] = [
        Self::Css,
        Self::JavaScript,
        Self::Xml,
        Self::Yaml,
        Self::None,
        Self::Error,
    ];

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Css => "css",
            Self::JavaScript => "javascript",
            Self::Xml => "xml",
            Self::Yaml => "yaml",
            Self::None => "none",
            Self::Error => "error",
        }
    }
}

impl FromStr for Language {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "css" => Language::Css,
            "javascript" => Language::JavaScript,
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
