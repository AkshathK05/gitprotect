pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

pub fn has_sensitive_keyword(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("key")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("pwd")
        || lower.contains("password")
        || lower.contains("auth")
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuotedLiteral {
    pub value: String,
    pub quote_char: char,
}

pub fn extract_quoted_literals(line: &str) -> Vec<QuotedLiteral> {
    let mut literals = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        if ch == '"' || ch == '\'' || ch == '`' {
            let quote = ch;
            let mut end = i + 1;
            let mut escaped = false;
            let mut found = false;

            while end < len {
                let c = chars[end];
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == quote {
                    found = true;
                    break;
                }
                end += 1;
            }

            if found {
                let value: String = chars[i + 1..end].iter().collect();
                literals.push(QuotedLiteral {
                    value,
                    quote_char: quote,
                });
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }

    literals
}

pub fn scan_entropy(line: &str) -> Vec<String> {
    if !has_sensitive_keyword(line) {
        return Vec::new();
    }

    let mut suspicious = Vec::new();
    let literals = extract_quoted_literals(line);

    for lit in literals {
        let text = lit.value;
        if text.len() < 20 {
            continue;
        }
        if text.contains("://") {
            continue;
        }
        if is_uuid(&text) {
            continue;
        }

        let is_hex = text.chars().all(|c| c.is_ascii_hexdigit());
        let threshold = if is_hex { 3.0 } else { 4.5 };
        let entropy = shannon_entropy(text.as_bytes());

        if entropy > threshold {
            suspicious.push(text);
        }
    }

    suspicious
}