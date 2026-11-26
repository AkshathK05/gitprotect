use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::{Regex, RegexSet};
use serde::Deserialize;
use std::collections::HashMap;

use crate::types::Severity;

pub const SEC_RULES_TOML: &str = include_str!("../../../rules/sec.toml");
pub const FILE_RULES_TOML: &str = include_str!("../../../rules/file.toml");
pub const BAAS_RULES_TOML: &str = include_str!("../../../rules/baas.toml");
pub const CODE_RULES_TOML: &str = include_str!("../../../rules/code.toml");

#[derive(Debug, Clone, Deserialize)]
pub struct RawRule {
    pub id: String,
    pub severity: Severity,
    pub kind: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub globs: Vec<String>,
    pub title: String,
    pub what_happened: String,
    pub fix_steps: Vec<String>,
    pub rotate_url: Option<String>,
    #[serde(default)]
    pub path_include: Vec<String>,
    #[serde(default)]
    pub path_exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    pub rule: Vec<RawRule>,
}

#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub what_happened: String,
    pub fix_steps: Vec<String>,
    pub rotate_url: Option<String>,
}

#[derive(Debug)]
pub struct CompiledLineRule {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub what_happened: String,
    pub fix_steps: Vec<String>,
    pub rotate_url: Option<String>,
    pub path_include: Option<GlobSet>,
    pub path_exclude: Option<GlobSet>,
}

#[derive(Debug)]
pub struct CompiledPathRule {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub what_happened: String,
    pub fix_steps: Vec<String>,
    pub rotate_url: Option<String>,
    pub globs: GlobSet,
    pub path_exclude: Option<GlobSet>,
}

#[derive(Debug)]
pub enum RuleLoadError {
    TomlError(String),
    RegexError {
        rule_id: String,
        pattern: String,
        message: String,
    },
    GlobError {
        rule_id: String,
        pattern: String,
        message: String,
    },
}

impl std::fmt::Display for RuleLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleLoadError::TomlError(msg) => write!(f, "Failed to parse rule TOML: {msg}"),
            RuleLoadError::RegexError {
                rule_id,
                pattern,
                message,
            } => {
                write!(
                    f,
                    "Invalid regex in rule {rule_id} (pattern '{pattern}'): {message}"
                )
            }
            RuleLoadError::GlobError {
                rule_id,
                pattern,
                message,
            } => {
                write!(
                    f,
                    "Invalid glob in rule {rule_id} (pattern '{pattern}'): {message}"
                )
            }
        }
    }
}

impl std::error::Error for RuleLoadError {}

#[derive(Debug)]
pub struct RuleEngine {
    pub line_rules: Vec<CompiledLineRule>,
    pub path_rules: Vec<CompiledPathRule>,
    pub line_regex_set: RegexSet,
    pub line_regexes: Vec<Regex>,
    pub pattern_to_rule_index: Vec<usize>,
    pub metadata_by_id: HashMap<String, RuleMetadata>,
}

impl RuleEngine {
    pub fn load_embedded() -> Result<Self, RuleLoadError> {
        let sources = [
            SEC_RULES_TOML,
            FILE_RULES_TOML,
            BAAS_RULES_TOML,
            CODE_RULES_TOML,
        ];

        let mut all_raw_rules = Vec::new();
        for src in sources {
            let file: RuleFile =
                toml::from_str(src).map_err(|e| RuleLoadError::TomlError(e.to_string()))?;
            all_raw_rules.extend(file.rule);
        }

        Self::compile(all_raw_rules)
    }

    pub fn compile(raw_rules: Vec<RawRule>) -> Result<Self, RuleLoadError> {
        let mut line_rules = Vec::new();
        let mut path_rules = Vec::new();
        let mut all_patterns = Vec::new();
        let mut pattern_to_rule_index = Vec::new();
        let mut metadata_by_id = HashMap::new();

        for raw in raw_rules {
            metadata_by_id
                .entry(raw.id.clone())
                .or_insert_with(|| RuleMetadata {
                    id: raw.id.clone(),
                    severity: raw.severity,
                    title: raw.title.clone(),
                    what_happened: raw.what_happened.clone(),
                    fix_steps: raw.fix_steps.clone(),
                    rotate_url: raw.rotate_url.clone(),
                });

            if raw.kind == "line" {
                let rule_idx = line_rules.len();

                let path_include = if !raw.path_include.is_empty() {
                    let mut builder = GlobSetBuilder::new();
                    for pat in &raw.path_include {
                        let glob = GlobBuilder::new(pat)
                            .case_insensitive(true)
                            .build()
                            .map_err(|e| RuleLoadError::GlobError {
                                rule_id: raw.id.clone(),
                                pattern: pat.clone(),
                                message: e.to_string(),
                            })?;
                        builder.add(glob);
                    }
                    Some(builder.build().map_err(|e| RuleLoadError::GlobError {
                        rule_id: raw.id.clone(),
                        pattern: "path_include".to_string(),
                        message: e.to_string(),
                    })?)
                } else {
                    None
                };

                let path_exclude = if !raw.path_exclude.is_empty() {
                    let mut builder = GlobSetBuilder::new();
                    for pat in &raw.path_exclude {
                        let glob = GlobBuilder::new(pat)
                            .case_insensitive(true)
                            .build()
                            .map_err(|e| RuleLoadError::GlobError {
                                rule_id: raw.id.clone(),
                                pattern: pat.clone(),
                                message: e.to_string(),
                            })?;
                        builder.add(glob);
                    }
                    Some(builder.build().map_err(|e| RuleLoadError::GlobError {
                        rule_id: raw.id.clone(),
                        pattern: "path_exclude".to_string(),
                        message: e.to_string(),
                    })?)
                } else {
                    None
                };

                for pat in &raw.patterns {
                    all_patterns.push((raw.id.clone(), pat.clone()));
                    pattern_to_rule_index.push(rule_idx);
                }

                line_rules.push(CompiledLineRule {
                    id: raw.id,
                    severity: raw.severity,
                    title: raw.title,
                    what_happened: raw.what_happened,
                    fix_steps: raw.fix_steps,
                    rotate_url: raw.rotate_url,
                    path_include,
                    path_exclude,
                });
            } else if raw.kind == "path" && !raw.globs.is_empty() {
                let mut glob_builder = GlobSetBuilder::new();
                for pat in &raw.globs {
                    let glob = GlobBuilder::new(pat)
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| RuleLoadError::GlobError {
                            rule_id: raw.id.clone(),
                            pattern: pat.clone(),
                            message: e.to_string(),
                        })?;
                    glob_builder.add(glob);
                }
                let globs = glob_builder.build().map_err(|e| RuleLoadError::GlobError {
                    rule_id: raw.id.clone(),
                    pattern: "globs".to_string(),
                    message: e.to_string(),
                })?;

                let path_exclude = if !raw.path_exclude.is_empty() {
                    let mut builder = GlobSetBuilder::new();
                    for pat in &raw.path_exclude {
                        let glob = GlobBuilder::new(pat)
                            .case_insensitive(true)
                            .build()
                            .map_err(|e| RuleLoadError::GlobError {
                                rule_id: raw.id.clone(),
                                pattern: pat.clone(),
                                message: e.to_string(),
                            })?;
                        builder.add(glob);
                    }
                    Some(builder.build().map_err(|e| RuleLoadError::GlobError {
                        rule_id: raw.id.clone(),
                        pattern: "path_exclude".to_string(),
                        message: e.to_string(),
                    })?)
                } else {
                    None
                };

                path_rules.push(CompiledPathRule {
                    id: raw.id,
                    severity: raw.severity,
                    title: raw.title,
                    what_happened: raw.what_happened,
                    fix_steps: raw.fix_steps,
                    rotate_url: raw.rotate_url,
                    globs,
                    path_exclude,
                });
            }
        }

        let pattern_strings: Vec<&str> = all_patterns.iter().map(|(_, p)| p.as_str()).collect();
        let line_regex_set =
            RegexSet::new(&pattern_strings).map_err(|e| RuleLoadError::RegexError {
                rule_id: "regex_set".to_string(),
                pattern: "combined".to_string(),
                message: e.to_string(),
            })?;

        let mut line_regexes = Vec::with_capacity(all_patterns.len());
        for (rule_id, pat) in &all_patterns {
            let re = Regex::new(pat).map_err(|e| RuleLoadError::RegexError {
                rule_id: rule_id.clone(),
                pattern: pat.clone(),
                message: e.to_string(),
            })?;
            line_regexes.push(re);
        }

        Ok(Self {
            line_rules,
            path_rules,
            line_regex_set,
            line_regexes,
            pattern_to_rule_index,
            metadata_by_id,
        })
    }

    pub fn get_rule_metadata(&self, rule_id: &str) -> Option<&RuleMetadata> {
        self.metadata_by_id.get(rule_id)
    }
}
