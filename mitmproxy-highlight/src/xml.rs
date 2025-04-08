use super::common::highlight;
use super::{Chunk, Tag};
use anyhow::Result;
use std::sync::LazyLock;
use tree_sitter_highlight::HighlightConfiguration;

const NAMES: &[&str] = &[
    "tag",      // <div>
    "property", // class or style
    "operator", // equal sign between class and value
    "comment",  // <!-- comment -->
    "punctuation",
    "markup",
];
const TAGS: &[Tag] = &[
    Tag::Name,    // <div>
    Tag::Name,    // class or style
    Tag::Name,    // equal sign between class and value
    Tag::Comment, // <!-- comment -->
    Tag::Name,    // punctuation
    Tag::Text,    // markup
];

static XML_CONFIG: LazyLock<HighlightConfiguration> = LazyLock::new(|| {
    let mut config = HighlightConfiguration::new(
        tree_sitter_xml::LANGUAGE_XML.into(),
        "",
        tree_sitter_xml::XML_HIGHLIGHT_QUERY,
        "",
        "",
    )
    .expect("failed to build XML syntax highlighter");
    config.configure(NAMES);
    config
});

pub fn highlight_xml(input: &[u8]) -> Result<Vec<Chunk>> {
    highlight(&XML_CONFIG, TAGS, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common;

    #[ignore]
    #[test]
    fn debug() {
        common::debug(
            tree_sitter_xml::LANGUAGE_XML.into(),
            tree_sitter_xml::XML_HIGHLIGHT_QUERY,
            b"<div class=\"test\">Hello</div><!-- comment -->",
        );
    }

    #[test]
    fn test_tags_ok() {
        common::test_names_ok(
            tree_sitter_xml::LANGUAGE_XML.into(),
            tree_sitter_xml::XML_HIGHLIGHT_QUERY,
            NAMES,
            TAGS,
        );
    }

    #[test]
    fn test_highlight_xml() {
        let input = b"<div class=\"test\">Hello</div><!-- comment -->";
        let chunks = highlight_xml(input).unwrap();
        assert_eq!(
            chunks,
            vec![
                (Tag::Name, "<div class=\"".to_string()),
                (Tag::Text, "test".to_string()),
                (Tag::Name, "\">".to_string()),
                (Tag::Text, "Hello".to_string()),
                (Tag::Name, "</div>".to_string()),
                (Tag::Comment, "<!-- comment -->".to_string())
            ]
        );
    }
}
