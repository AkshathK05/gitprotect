use std::collections::HashSet;

use crate::types::{Decision, Finding, Severity};

pub fn decide(
    findings: Vec<Finding>,
    baseline: &HashSet<String>,
    ignored: &HashSet<String>,
) -> Decision {
    let mut seen_fingerprints = HashSet::new();
    let mut blocking = Vec::new();
    let mut warnings = Vec::new();
    let mut info = Vec::new();

    for finding in findings {
        if baseline.contains(&finding.fingerprint) || ignored.contains(&finding.fingerprint) {
            continue;
        }
        if !seen_fingerprints.insert(finding.fingerprint.clone()) {
            continue;
        }
        match finding.severity {
            Severity::Block => blocking.push(finding),
            Severity::Warn => warnings.push(finding),
            Severity::Info => info.push(finding),
        }
    }

    let exit_code = if blocking.is_empty() { 0 } else { 1 };

    Decision {
        exit_code,
        blocking,
        warnings,
        info,
    }
}
