use sha2::{Digest, Sha256};
use std::fmt::Write;

pub fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

pub fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

pub fn compute_fingerprint(rule_id: &str, path: &str, matched_text: &str) -> String {
    let norm_path = normalize_path(path);
    let collapsed_text = collapse_whitespace(matched_text);

    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(norm_path.as_bytes());
    hasher.update([0x00]);
    hasher.update(collapsed_text.as_bytes());

    let result = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for byte in &result[..8] {
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}
