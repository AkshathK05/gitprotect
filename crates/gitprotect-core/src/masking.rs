pub fn redaction_tag(rule_id: &str) -> String {
    format!("[REDACTED_{rule_id}]")
}

pub fn mask_secret(snippet: &str, secret: &str, rule_id: &str) -> String {
    let tag = redaction_tag(rule_id);
    snippet.replace(secret, &tag)
}

pub fn mask_span(original: &str, range: std::ops::Range<usize>, rule_id: &str) -> String {
    if range.start > range.end
        || range.end > original.len()
        || !original.is_char_boundary(range.start)
        || !original.is_char_boundary(range.end)
    {
        return original.to_string();
    }
    let tag = redaction_tag(rule_id);
    let mut masked = String::with_capacity(original.len() + tag.len());
    masked.push_str(&original[..range.start]);
    masked.push_str(&tag);
    masked.push_str(&original[range.end..]);
    masked
}
