use gitprotect_core::{Decision, RuleEngine};
use std::io::Write;

pub fn print_text_report(
    decision: &Decision,
    engine: &RuleEngine,
    verbose: bool,
    writer: &mut dyn Write,
) -> std::io::Result<()> {
    if !decision.blocking.is_empty() {
        writeln!(writer, "gitprotect: BLOCKING SECURITY ISSUES DETECTED\n")?;
        for finding in &decision.blocking {
            let meta = engine.get_rule_metadata(&finding.rule_id);
            let title = meta
                .map(|m| m.title.as_str())
                .unwrap_or("Security Rule Violation");
            let what_happened = meta
                .map(|m| m.what_happened.as_str())
                .unwrap_or("A security violation was found.");

            writeln!(
                writer,
                "  [BLOCK] {} - {} ({}:{})",
                finding.rule_id, title, finding.path, finding.line
            )?;
            writeln!(writer, "    Snippet: {}", finding.masked_snippet)?;
            writeln!(writer, "    What happened: {}", what_happened)?;

            if let Some(m) = meta {
                if !m.fix_steps.is_empty() {
                    writeln!(writer, "    How to fix:")?;
                    for (i, step) in m.fix_steps.iter().enumerate() {
                        writeln!(writer, "      {}. {}", i + 1, step)?;
                    }
                }
                if let Some(rotate) = &m.rotate_url {
                    writeln!(writer, "    Rotate URL: {}", rotate)?;
                }
            }

            if finding.rule_id.starts_with("SEC-") {
                writeln!(
                    writer,
                    "    Note: If this was already pushed, rotate the key; removing it from git does not make it safe."
                )?;
            }
            writeln!(writer)?;
        }
    }

    if !decision.warnings.is_empty() {
        for finding in &decision.warnings {
            writeln!(
                writer,
                "  [WARN] {} ({}:{}): {}",
                finding.rule_id, finding.path, finding.line, finding.masked_snippet
            )?;
        }
        if !decision.blocking.is_empty() {
            writeln!(writer)?;
        }
    }

    if verbose && !decision.info.is_empty() {
        for finding in &decision.info {
            writeln!(
                writer,
                "  [INFO] {} ({}:{}): {}",
                finding.rule_id, finding.path, finding.line, finding.masked_snippet
            )?;
        }
        writeln!(writer)?;
    }

    if !decision.blocking.is_empty() {
        writeln!(
            writer,
            "Commit blocked by gitprotect. Resolve the BLOCK issues above before committing."
        )?;
    }

    Ok(())
}

pub fn print_json_report(decision: &Decision, writer: &mut dyn Write) -> std::io::Result<()> {
    let json =
        serde_json::to_string_pretty(decision).map_err(|e| std::io::Error::other(e.to_string()))?;
    writeln!(writer, "{json}")
}
