use super::common;
use super::{Chunk, Tag};
use anyhow::Result;
use std::sync::LazyLock;
use tree_sitter_highlight::HighlightConfiguration;
use tree_sitter_xml::{LANGUAGE_XML as LANGUAGE, XML_HIGHLIGHT_QUERY as HIGHLIGHTS_QUERY};

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

static CONFIG: LazyLock<HighlightConfiguration> = LazyLock::new(|| {
    let mut config = HighlightConfiguration::new(LANGUAGE.into(), "", HIGHLIGHTS_QUERY, "", "")
        .expect("failed to build syntax highlighter");
    config.configure(NAMES);
    config
});

pub fn highlight(input: &[u8]) -> Result<Vec<Chunk>> {
    common::highlight(&CONFIG, TAGS, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn debug() {
        common::debug(
            LANGUAGE.into(),
            HIGHLIGHTS_QUERY,
            b"<div class=\"test\">Hello</div><!-- comment -->",
        );
    }

    #[test]
    fn test_tags_ok() {
        common::test_tags_ok(LANGUAGE.into(), HIGHLIGHTS_QUERY, NAMES, TAGS);
    }

    #[test]
    fn test_highlight() {
        let input = b"<div class=\"test\">Hello</div><!-- comment -->";
        let chunks = highlight(input).unwrap();
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
