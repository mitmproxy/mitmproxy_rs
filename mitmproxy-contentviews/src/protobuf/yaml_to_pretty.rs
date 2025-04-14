/// YAML value => prettified text
use crate::protobuf::view_protobuf::tags;
use regex::Captures;

// Helper method to apply regex replacements to the YAML output
pub(super) fn apply_replacements(yaml_str: &str) -> anyhow::Result<String> {
    // Replace !fixed32 tags with comments showing float and i32 interpretations
    let with_fixed32 = tags::FIXED32_RE.replace_all(yaml_str, |caps: &Captures| {
        let value = caps[1].parse::<u32>().unwrap_or_default();
        let float_value = f32::from_bits(value);
        let i32_value = value as i32;

        if !float_value.is_nan() && float_value < 0.0 {
            format!(
                "{} {} # float: {}, i32: {}",
                *tags::FIXED32,
                value,
                float_value,
                i32_value
            )
        } else if !float_value.is_nan() {
            format!("{} {} # float: {}", *tags::FIXED32, value, float_value)
        } else if i32_value < 0 {
            format!("{} {} # i32: {}", *tags::FIXED32, value, i32_value)
        } else {
            format!("{} {}", *tags::FIXED32, value)
        }
    });

    // Replace !fixed64 tags with comments showing double and i64 interpretations
    let with_fixed64 = tags::FIXED64_RE.replace_all(&with_fixed32, |caps: &Captures| {
        let value = caps[1].parse::<u64>().unwrap_or_default();
        let double_value = f64::from_bits(value);
        let i64_value = value as i64;

        if !double_value.is_nan() && double_value < 0.0 {
            format!(
                "{} {} # double: {}, i64: {}",
                *tags::FIXED64,
                value,
                double_value,
                i64_value
            )
        } else if !double_value.is_nan() {
            format!("{} {} # double: {}", *tags::FIXED64, value, double_value)
        } else if i64_value < 0 {
            format!("{} {} # i64: {}", *tags::FIXED64, value, i64_value)
        } else {
            format!("{} {}", *tags::FIXED64, value)
        }
    });

    // Replace !varint tags with comments showing signed interpretation if different
    let with_varint = tags::VARINT_RE.replace_all(&with_fixed64, |caps: &Captures| {
        let unsigned_value = caps[1].parse::<u64>().unwrap_or_default();
        let i64_zigzag = decode_zigzag64(unsigned_value);

        // Only show signed value if it's different from unsigned
        if i64_zigzag < 0 {
            format!("{} # signed: {}", unsigned_value, i64_zigzag)
        } else {
            unsigned_value.to_string()
        }
    });

    Ok(with_varint.to_string())
}

// Decode a zigzag-encoded 64-bit integer
fn decode_zigzag64(n: u64) -> i64 {
    ((n >> 1) as i64) ^ (-((n & 1) as i64))
}
