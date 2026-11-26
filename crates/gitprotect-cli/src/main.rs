#![forbid(unsafe_code)]

mod cli;
mod config;
mod diff;
mod doctor;
mod git;
mod hook;
mod report;

use anyhow::{Context, Result};
use clap::Parser;
use gitprotect_core::{Finding, RuleEngine, ScanOptions, decide, scan_input};
use std::io;

use cli::{Cli, Commands, FormatOption};
use config::{load_baseline, load_config, save_baseline};
use diff::parse_unified_diff;
use doctor::run_doctor;
use git::{
    get_cached_diff, get_empty_tree_hash, get_file_size, get_range_diff, get_repo_root,
    read_gitignore,
};
use hook::{
    install_global_hooks, install_repo_hooks, run_pre_commit, run_pre_push, uninstall_global_hooks,
    uninstall_repo_hooks,
};
use report::{print_json_report, print_text_report};

fn main() {
    let args = Cli::parse();

    let exit_code = match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gitprotect: error: {e:#}");
            1
        }
    };

    std::process::exit(exit_code);
}

fn collect_current_inputs() -> Vec<gitprotect_core::ScanInput> {
    let diff = get_cached_diff().unwrap_or_default();
    let mut inputs = parse_unified_diff(&diff);

    if inputs.is_empty() {
        inputs = get_empty_tree_hash()
            .and_then(|empty_tree| get_range_diff(&empty_tree, "HEAD"))
            .map(|tree_diff| parse_unified_diff(&tree_diff))
            .unwrap_or_default();
    }

    for input in &mut inputs {
        input.size_bytes = get_file_size(&input.path, None);
    }

    inputs
}

fn run(args: Cli) -> Result<i32> {
    match args.command {
        Commands::Init { global, force } => {
            if global {
                install_global_hooks(force)?;
            } else {
                install_repo_hooks()?;
            }
            Ok(0)
        }
        Commands::Uninstall { global } => {
            if global {
                uninstall_global_hooks()?;
            } else {
                uninstall_repo_hooks()?;
            }
            Ok(0)
        }
        Commands::Doctor => {
            let res = run_doctor()?;
            if res.all_passed { Ok(0) } else { Ok(1) }
        }
        Commands::Baseline => {
            let engine = RuleEngine::load_embedded().context("Failed to load embedded rules")?;
            let repo_root = get_repo_root()?;
            let gitignore_content = read_gitignore(&repo_root);

            let inputs = collect_current_inputs();

            let options = ScanOptions {
                max_file_bytes: 5_000_000,
                disabled_rules: std::collections::HashSet::new(),
                gitignore_content,
            };

            let mut fingerprints = Vec::new();
            for input in &inputs {
                let findings = scan_input(input, &engine, &options);
                for f in findings {
                    fingerprints.push(f.fingerprint);
                }
            }

            save_baseline(&repo_root, &fingerprints)?;
            println!(
                "gitprotect: Recorded {} finding fingerprints to .gitprotect-baseline.json",
                fingerprints.len()
            );
            Ok(0)
        }
        Commands::Scan {
            staged: _,
            format,
            verbose,
        } => {
            let engine = RuleEngine::load_embedded().context("Failed to load embedded rules")?;
            let repo_root = get_repo_root()?;
            let config = load_config(&repo_root);
            let baseline = load_baseline(&repo_root);
            let gitignore_content = read_gitignore(&repo_root);

            let inputs = collect_current_inputs();

            let options = ScanOptions {
                max_file_bytes: config.max_file_bytes.unwrap_or(5_000_000),
                disabled_rules: config.disable_rules.clone(),
                gitignore_content,
            };

            let mut all_findings: Vec<Finding> = Vec::new();
            for input in &inputs {
                all_findings.extend(scan_input(input, &engine, &options));
            }

            let decision = decide(all_findings, &baseline, &config.ignore);

            match format {
                FormatOption::Json => {
                    print_json_report(&decision, &mut io::stdout())?;
                }
                FormatOption::Text => {
                    print_text_report(&decision, &engine, verbose, &mut io::stdout())?;
                }
            }

            Ok(decision.exit_code)
        }
        Commands::Hook { name } => {
            let engine = match RuleEngine::load_embedded() {
                Ok(e) => e,
                Err(err) => {
                    // A3.4: Fail-open on internal errors in hook mode
                    eprintln!("gitprotect: warning: failed to load rules (failing open): {err}");
                    return Ok(0);
                }
            };

            if name == "pre-commit" {
                match run_pre_commit(&engine) {
                    Ok(code) => Ok(code),
                    Err(err) => {
                        // A3.4: Fail-open on internal or git errors
                        eprintln!(
                            "gitprotect: warning: pre-commit hook error (failing open): {err}"
                        );
                        Ok(0)
                    }
                }
            } else if name == "pre-push" {
                match run_pre_push(&engine) {
                    Ok(code) => Ok(code),
                    Err(err) => {
                        // A3.4: Fail-open on internal or git errors
                        eprintln!("gitprotect: warning: pre-push hook error (failing open): {err}");
                        Ok(0)
                    }
                }
            } else {
                eprintln!("gitprotect: warning: unsupported hook '{name}' (failing open)");
                Ok(0)
            }
        }
    }
}
