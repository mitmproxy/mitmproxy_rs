/// YAML value => prettified text
use crate::protobuf::view_protobuf::tags;
use regex::Captures;
use std::fmt::{Display, Formatter};

/// Collect all representations of a number and output the "best" one as the YAML value
/// and the rest as comments.
struct NumReprs(Vec<(&'static str, String)>);

impl NumReprs {
    fn new(k: &'static str, v: impl ToString) -> Self {
        let mut inst = Self(Vec::with_capacity(3));
        inst.push(k, v);
        inst
    }
    fn push(&mut self, k: &'static str, v: impl ToString) {
        self.0.push((k, v.to_string()));
    }
}

impl Display for NumReprs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // We first sort by t.len(), which is a hack to make sure that sint is not used
        // as the main representation.
        let (min_typ, min_val) = self
            .0
            .iter()
            .min_by_key(|(t, v)| (t.len(), v.len()))
            .unwrap();
        let mut i = self.0.iter().filter(|(t, _)| t != min_typ);

        write!(f, "{}", min_val)?;
        if let Some((t, v)) = i.next() {
            write!(f, "  # {}: {}", t, v)?;
        }
        for (t, v) in i {
            write!(f, ", {}: {}", t, v)?;
        }
        Ok(())
    }
}

// Helper method to apply regex replacements to the YAML output
pub(super) fn apply_replacements(yaml_str: &str) -> anyhow::Result<String> {
    // Replace !fixed32 tags with comments showing float and i32 interpretations
    let with_fixed32 = tags::FIXED32_RE.replace_all(yaml_str, |caps: &Captures| {
        let value = caps[1].parse::<u32>().unwrap_or_default();
        let mut repr = NumReprs::new("u32", value);

        let float_value = f32::from_bits(value);
        if !float_value.is_nan() && float_value.abs() > 0.0000001 {
            repr.push("f32", format_float(float_value));
        }

        if value.leading_zeros() == 0 {
            repr.push("i32", value as i32);
        }
        format!("{} {}", *tags::FIXED32, repr)
    });

    // Replace !fixed64 tags with comments showing double and i64 interpretations
    let with_fixed64 = tags::FIXED64_RE.replace_all(&with_fixed32, |caps: &Captures| {
        let value = caps[1].parse::<u64>().unwrap_or_default();
        let mut repr = NumReprs::new("u64", value);

        let double_value = f64::from_bits(value);
        if !double_value.is_nan() && double_value.abs() > 0.0000001 {
            repr.push("f64", format_float(double_value));
        }

        if value.leading_zeros() == 0 {
            repr.push("i64", value as i64);
        }
        format!("{} {}", *tags::FIXED64, repr)
    });

    // Replace !varint tags with comments showing signed interpretation if different
    let with_varint = tags::VARINT_RE.replace_all(&with_fixed64, |caps: &Captures| {
        let value = caps[1].parse::<u64>().unwrap_or_default();
        let mut repr = NumReprs::new("u64", value);

        if value.leading_zeros() == 0 {
            repr.push("i64", value as i64);
            // We only show u64 and i64 reprs if the leading bit is a 1.
            // It could technically be zigzag, but the odds are quite low.
        } else {
            repr.push("!sint", decode_zigzag64(value));
        }

        repr.to_string()
    });

    Ok(with_varint.to_string())
}

/// Ensure that floating point numbers have a ".0" component so that we roundtrip.
fn format_float<T: Display>(val: T) -> String {
    let mut ret = format!("{:.}", val);
    if !ret.contains(".") {
        ret.push_str(".0");
    }
    ret
}

// Decode a zigzag-encoded 64-bit integer
fn decode_zigzag64(n: u64) -> i64 {
    ((n >> 1) as i64) ^ (-((n & 1) as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_float() {
        assert_eq!(format_float(1.2345), "1.2345");
        assert_eq!(format_float(0f32), "0.0");
        assert_eq!(format_float(-1f64), "-1.0");
    }

    #[test]
    fn test_decode_zigzag64() {
        assert_eq!(decode_zigzag64(0), 0);
        assert_eq!(decode_zigzag64(1), -1);
        assert_eq!(decode_zigzag64(2), 1);
        assert_eq!(decode_zigzag64(3), -2);
        assert_eq!(decode_zigzag64(0xfffffffe), 0x7fffffff);
        assert_eq!(decode_zigzag64(0xffffffff), -0x80000000);
    }
}
