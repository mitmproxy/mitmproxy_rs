use super::common::highlight;
use super::Chunk;
use anyhow::Result;

pub(crate) const XML_TAGS: &[&str] = &[
    "tag",      // <div>
    "property", // class or style
    "comment",  // <!-- comment -->
    "punctuation",
    "markup",
];

pub fn highlight_xml(input: &[u8]) -> Result<Vec<Chunk>> {
    // There also is tree_sitter_xml, but tree_sitter_html produces slightly nicer output for us.
    highlight(
        tree_sitter_xml::LANGUAGE_XML.into(),
        tree_sitter_xml::XML_HIGHLIGHT_QUERY,
        XML_TAGS,
        input,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax_highlight::common;

    #[test]
    fn test_tags_ok() {
        common::test_tags_ok(
            tree_sitter_xml::LANGUAGE_XML.into(),
            tree_sitter_xml::XML_HIGHLIGHT_QUERY,
            XML_TAGS,
        );
    }

    #[test]
    fn test_highlight_xml() {
        let input = b"<div class=\"test\">Hello</div><!-- comment -->";
        let chunks = highlight_xml(input).unwrap();
        assert_eq!(
            chunks,
            vec![
                ("punctuation", "<".to_string()),
                ("tag", "div".to_string()),
                ("", " ".to_string()),
                ("property", "class".to_string()),
                ("", "=".to_string()),
                ("punctuation", "\"".to_string()),
                ("", "test".to_string()),
                ("punctuation", "\">".to_string()),
                ("markup", "Hello".to_string()),
                ("punctuation", "</".to_string()),
                ("tag", "div".to_string()),
                ("punctuation", ">".to_string()),
                ("comment", "<!-- comment -->".to_string())
            ]
        );
    }
}
