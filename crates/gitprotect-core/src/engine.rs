use std::collections::HashSet;
use std::path::Path;

use crate::entropy::scan_entropy;
use crate::fingerprint::{compute_fingerprint, normalize_path};
use crate::masking::{mask_secret, mask_span};
use crate::rule::RuleEngine;
use crate::types::{Finding, ScanInput, Severity};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_file_bytes: u64,
    pub disabled_rules: HashSet<String>,
    pub gitignore_content: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 5_000_000,
            disabled_rules: HashSet::new(),
            gitignore_content: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LineIgnore {
    None,
    All,
    Rules(HashSet<String>),
}

impl LineIgnore {
    pub fn ignores(&self, rule_id: &str) -> bool {
        match self {
            LineIgnore::None => false,
            LineIgnore::All => true,
            LineIgnore::Rules(rules) => rules.contains(rule_id),
        }
    }
}

pub fn parse_line_ignore(line: &str) -> LineIgnore {
    if !line.contains("gitprotect:ignore") {
        return LineIgnore::None;
    }

    let mut rules = HashSet::new();
    let mut parts = line.split("gitprotect:ignore");
    // Skip the first part before the first gitprotect:ignore
    parts.next();

    let mut saw_bare = false;

    for part in parts {
        let remainder = part.trim_start();
        if remainder.is_empty() {
            saw_bare = true;
            continue;
        }

        let first_token = remainder
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '*' || c == '/')
            .next()
            .unwrap_or("");

        if first_token.is_empty() {
            saw_bare = true;
        } else if first_token.contains('-')
            || first_token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            rules.insert(first_token.to_string());
        } else {
            saw_bare = true;
        }
    }

    if saw_bare && rules.is_empty() {
        LineIgnore::All
    } else if !rules.is_empty() {
        LineIgnore::Rules(rules)
    } else {
        LineIgnore::All
    }
}

pub fn should_skip_line_engine_for_path(path_str: &str) -> bool {
    let norm = normalize_path(path_str);
    let path = Path::new(&norm);
    let filename = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => return false,
    };

    let filename_lower = filename.to_ascii_lowercase();

    // Lockfiles
    if matches!(
        filename_lower.as_str(),
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "cargo.lock"
            | "uv.lock"
            | "poetry.lock"
    ) {
        return true;
    }

    // Minified JS
    if filename_lower.ends_with(".min.js") {
        return true;
    }

    // .DS_Store
    if filename_lower == ".ds_store" {
        return true;
    }

    false
}

pub fn gitignore_has_env_rule(gitignore_content: &str) -> bool {
    for line in gitignore_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(".env") {
            return true;
        }
    }
    false
}

pub fn scan_input(input: &ScanInput, engine: &RuleEngine, options: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    let norm_path = normalize_path(&input.path);
    let path = Path::new(&norm_path);
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // 1. Path-based rules (compiled from TOML)
    for path_rule in &engine.path_rules {
        if options.disabled_rules.contains(&path_rule.id) {
            continue;
        }

        if path_rule.globs.is_match(&norm_path) {
            let is_excluded = path_rule
                .path_exclude
                .as_ref()
                .is_some_and(|exclude| exclude.is_match(&norm_path));
            if is_excluded {
                continue;
            }

            let fp = compute_fingerprint(&path_rule.id, &norm_path, &norm_path);
            findings.push(Finding {
                rule_id: path_rule.id.clone(),
                severity: path_rule.severity,
                path: norm_path.clone(),
                line: 0,
                masked_snippet: format!("Forbidden file matched rule: {}", norm_path),
                fingerprint: fp,
            });
        }
    }

    // Special path checks:
    // FILE-002: WARN *.sql only if basename contains dump or backup, or size > 1_000_000 bytes
    if !options.disabled_rules.contains("FILE-002") && filename.ends_with(".sql") {
        let is_dump_or_backup = filename.contains("dump") || filename.contains("backup");
        let is_large = input.size_bytes.is_some_and(|s| s > 1_000_000);

        if is_dump_or_backup || is_large {
            let reason = if is_dump_or_backup && is_large {
                "SQL file name contains dump/backup and size > 1MB"
            } else if is_dump_or_backup {
                "SQL file name contains dump/backup"
            } else {
                "SQL file size > 1MB"
            };

            let fp = compute_fingerprint("FILE-002", &norm_path, reason);
            findings.push(Finding {
                rule_id: "FILE-002".to_string(),
                severity: Severity::Warn,
                path: norm_path.clone(),
                line: 0,
                masked_snippet: format!("{}: {}", reason, norm_path),
                fingerprint: fp,
            });
        }
    }

    // FILE-003: WARN if a staged path is .env or .env.example and the repo's .gitignore has no line starting with .env
    if !options.disabled_rules.contains("FILE-003")
        && (filename == ".env" || filename == ".env.example")
    {
        let has_env_rule = match &options.gitignore_content {
            Some(content) => gitignore_has_env_rule(content),
            None => false,
        };

        if !has_env_rule {
            let fp = compute_fingerprint("FILE-003", &norm_path, "missing_env_in_gitignore");
            findings.push(Finding {
                rule_id: "FILE-003".to_string(),
                severity: Severity::Warn,
                path: norm_path.clone(),
                line: 0,
                masked_snippet: ".gitignore does not contain a rule starting with .env".to_string(),
                fingerprint: fp,
            });
        }
    }

    // FILE-004: WARN files larger than config max_file_bytes (default 5_000_000)
    let is_oversized = !options.disabled_rules.contains("FILE-004")
        && input
            .size_bytes
            .is_some_and(|size| size > options.max_file_bytes);
    if is_oversized {
        let size = input.size_bytes.unwrap_or(0);
        let fp = compute_fingerprint("FILE-004", &norm_path, "file_exceeds_max_bytes");
        findings.push(Finding {
            rule_id: "FILE-004".to_string(),
            severity: Severity::Warn,
            path: norm_path.clone(),
            line: 0,
            masked_snippet: format!(
                "File size ({} bytes) exceeds limit ({} bytes)",
                size, options.max_file_bytes
            ),
            fingerprint: fp,
        });
    }

    // 2. Line engine skips: binary, lockfiles, *.min.js, .DS_Store
    if should_skip_line_engine_for_path(&norm_path) {
        return findings;
    }

    // 3. Line engine matching
    for (line_num, line_text) in &input.added_lines {
        let line_ignore = parse_line_ignore(line_text);
        if line_ignore == LineIgnore::All {
            continue;
        }

        // RegexSet matching
        let matches = engine.line_regex_set.matches(line_text);
        for pat_idx in matches {
            let rule_idx = engine.pattern_to_rule_index[pat_idx];
            let rule = &engine.line_rules[rule_idx];

            if options.disabled_rules.contains(&rule.id) {
                continue;
            }
            if line_ignore.ignores(&rule.id) {
                continue;
            }

            // Path inclusion/exclusion
            let include_failed = rule
                .path_include
                .as_ref()
                .is_some_and(|include| !include.is_match(&norm_path));
            if include_failed {
                continue;
            }

            let exclude_matched = rule
                .path_exclude
                .as_ref()
                .is_some_and(|exclude| exclude.is_match(&norm_path));
            if exclude_matched {
                continue;
            }

            // Locate exact match span
            if let Some(m) = engine.line_regexes[pat_idx].find(line_text) {
                let matched_secret = m.as_str();
                let fp = compute_fingerprint(&rule.id, &norm_path, matched_secret);
                let masked = mask_span(line_text, m.range(), &rule.id);

                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    path: norm_path.clone(),
                    line: *line_num,
                    masked_snippet: masked,
                    fingerprint: fp,
                });
            }
        }

        // SEC-005 Entropy check
        if !options.disabled_rules.contains("SEC-005") && !line_ignore.ignores("SEC-005") {
            let suspicious = scan_entropy(line_text);
            for secret_lit in suspicious {
                let fp = compute_fingerprint("SEC-005", &norm_path, &secret_lit);
                let masked = mask_secret(line_text, &secret_lit, "SEC-005");

                findings.push(Finding {
                    rule_id: "SEC-005".to_string(),
                    severity: Severity::Warn,
                    path: norm_path.clone(),
                    line: *line_num,
                    masked_snippet: masked,
                    fingerprint: fp,
                });
            }
        }
    }

    findings
}
