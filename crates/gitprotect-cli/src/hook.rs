use anyhow::{Context, Result, bail};
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use gitprotect_core::{Finding, RuleEngine, ScanOptions, decide, scan_input};

use crate::config::{load_baseline, load_config};
use crate::diff::parse_unified_diff;
use crate::doctor::get_global_hooks_dir;
use crate::git::{
    get_cached_diff, get_empty_tree_hash, get_file_size, get_git_config, get_hooks_dir,
    get_parent_commit, get_range_diff, get_repo_root, read_gitignore, rev_list_not_remotes,
    set_git_config_global, unset_git_config_global,
};
use crate::report::print_text_report;

pub const HOOK_NAMES: &[&str] = &["pre-commit", "pre-push"];

pub fn get_native_binary_path() -> Result<PathBuf> {
    let current = std::env::current_exe().context("Failed to get current executable path")?;
    let canonical = fs::canonicalize(&current).unwrap_or(current);
    Ok(canonical)
}

#[cfg(unix)]
pub fn make_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)
        .context("Failed to get file metadata")?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).context("Failed to set file permissions to 0755")?;
    Ok(())
}

#[cfg(not(unix))]
pub fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn format_hook_bin_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn generate_repo_hook_script(hook_name: &str, native_bin: &Path) -> String {
    let bin_path = format_hook_bin_path(native_bin);
    format!(
        r#"#!/bin/sh
# Managed by gitprotect
HOOK_NAME="{hook_name}"
ORIG_HOOK="$(dirname "$0")/${{HOOK_NAME}}.gitprotect-orig"
if [ -x "$ORIG_HOOK" ]; then
    "$ORIG_HOOK" "$@" || exit $?
fi

NATIVE_BIN="{bin_path}"
if [ -x "$NATIVE_BIN" ]; then
    exec "$NATIVE_BIN" hook "$HOOK_NAME" "$@"
fi

if command -v gitprotect >/dev/null 2>&1; then
    exec gitprotect hook "$HOOK_NAME" "$@"
fi

echo "gitprotect: warning: native binary not found at $NATIVE_BIN or in PATH, allowing hook to pass" >&2
exit 0
"#,
    )
}

pub fn generate_global_hook_script(hook_name: &str, native_bin: &Path) -> String {
    let bin_path = format_hook_bin_path(native_bin);
    format!(
        r#"#!/bin/sh
# Managed by gitprotect
HOOK_NAME="{hook_name}"
NATIVE_BIN="{bin_path}"

STDIN_DATA=$(cat)

run_gitprotect() {{
    if [ -x "$NATIVE_BIN" ]; then
        printf "%s" "$STDIN_DATA" | "$NATIVE_BIN" hook "$HOOK_NAME" "$@"
        return $?
    elif command -v gitprotect >/dev/null 2>&1; then
        printf "%s" "$STDIN_DATA" | gitprotect hook "$HOOK_NAME" "$@"
        return $?
    else
        echo "gitprotect: warning: native binary not found at $NATIVE_BIN or in PATH, allowing hook to pass" >&2
        return 0
    fi
}}

run_gitprotect "$@"
GP_STATUS=$?
if [ $GP_STATUS -ne 0 ]; then
    exit $GP_STATUS
fi

GIT_DIR=$(git rev-parse --git-dir 2>/dev/null)
if [ -n "$GIT_DIR" ]; then
    REPO_HOOK="$GIT_DIR/hooks/$HOOK_NAME"
    if [ -x "$REPO_HOOK" ]; then
        printf "%s" "$STDIN_DATA" | "$REPO_HOOK" "$@"
        exit $?
    fi
fi

exit 0
"#,
    )
}

pub fn install_repo_hooks() -> Result<()> {
    let hooks_dir = get_hooks_dir()?;
    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir)?;
    }

    let native_bin = get_native_binary_path()?;

    for hook_name in HOOK_NAMES {
        let hook_path = hooks_dir.join(hook_name);
        if hook_path.exists() {
            let content = fs::read_to_string(&hook_path).unwrap_or_default();
            if !content.contains("# Managed by gitprotect") {
                // Foreign hook: rename to <name>.gitprotect-orig per A3.5
                let orig_path = hooks_dir.join(format!("{hook_name}.gitprotect-orig"));
                fs::rename(&hook_path, &orig_path)
                    .with_context(|| format!("Failed to backup foreign hook to {:?}", orig_path))?;
            }
        }

        let script = generate_repo_hook_script(hook_name, &native_bin);
        fs::write(&hook_path, script)?;
        make_executable(&hook_path)?;
    }

    println!(
        "gitprotect: Successfully installed repository hooks in {}",
        hooks_dir.display()
    );
    Ok(())
}

pub fn install_global_hooks(force: bool) -> Result<()> {
    let global_hooks_dir = get_global_hooks_dir();
    let current_config = get_git_config("core.hooksPath", true);

    let global_dir_str = global_hooks_dir.to_string_lossy().to_string();

    if let Some(ref existing) = current_config {
        let mismatch = existing != &global_dir_str && !force;
        if mismatch {
            bail!(
                "global core.hooksPath is already set to '{}'. Use --force to overwrite.",
                existing
            );
        }
    }

    if !global_hooks_dir.exists() {
        fs::create_dir_all(&global_hooks_dir)?;
    }

    let native_bin = get_native_binary_path()?;

    for hook_name in HOOK_NAMES {
        let hook_path = global_hooks_dir.join(hook_name);
        let script = generate_global_hook_script(hook_name, &native_bin);
        fs::write(&hook_path, script)?;
        make_executable(&hook_path)?;
    }

    set_git_config_global("core.hooksPath", &global_dir_str)?;
    println!(
        "gitprotect: Successfully installed global hooks in {}",
        global_hooks_dir.display()
    );
    Ok(())
}

pub fn uninstall_repo_hooks() -> Result<()> {
    let hooks_dir = get_hooks_dir()?;
    if !hooks_dir.exists() {
        return Ok(());
    }

    for hook_name in HOOK_NAMES {
        let hook_path = hooks_dir.join(hook_name);
        if hook_path.exists() {
            let content = fs::read_to_string(&hook_path).unwrap_or_default();
            if content.contains("# Managed by gitprotect") {
                fs::remove_file(&hook_path)?;
            }
        }

        let orig_path = hooks_dir.join(format!("{hook_name}.gitprotect-orig"));
        if orig_path.exists() {
            fs::rename(&orig_path, &hook_path)?;
            println!("gitprotect: Restored foreign hook {}", hook_name);
        }
    }

    println!("gitprotect: Successfully uninstalled repository hooks");
    Ok(())
}

pub fn uninstall_global_hooks() -> Result<()> {
    let global_hooks_dir = get_global_hooks_dir();
    let global_dir_str = global_hooks_dir.to_string_lossy().to_string();

    let current_global = get_git_config("core.hooksPath", true);
    if current_global.as_deref() == Some(&global_dir_str) {
        unset_git_config_global("core.hooksPath")?;
    }

    for hook_name in HOOK_NAMES {
        let hook_path = global_hooks_dir.join(hook_name);
        if hook_path.exists() {
            let content = fs::read_to_string(&hook_path).unwrap_or_default();
            if content.contains("# Managed by gitprotect") {
                let _ = fs::remove_file(&hook_path);
            }
        }
    }

    println!("gitprotect: Successfully uninstalled global hooks");
    Ok(())
}

pub fn run_pre_commit(engine: &RuleEngine) -> Result<i32> {
    let repo_root = get_repo_root()?;
    let config = load_config(&repo_root);
    let baseline = load_baseline(&repo_root);
    let gitignore_content = read_gitignore(&repo_root);

    let diff = get_cached_diff()?;
    let mut inputs = parse_unified_diff(&diff);

    for input in &mut inputs {
        input.size_bytes = get_file_size(&input.path, None);
    }

    let options = ScanOptions {
        max_file_bytes: config.max_file_bytes.unwrap_or(5_000_000),
        disabled_rules: config.disable_rules.clone(),
        gitignore_content,
    };

    let mut all_findings = Vec::new();
    for input in &inputs {
        all_findings.extend(scan_input(input, engine, &options));
    }

    let decision = decide(all_findings, &baseline, &config.ignore);
    print_text_report(&decision, engine, false, &mut io::stderr())?;

    Ok(decision.exit_code)
}

pub fn run_pre_push(engine: &RuleEngine) -> Result<i32> {
    let repo_root = get_repo_root()?;
    let config = load_config(&repo_root);
    let baseline = load_baseline(&repo_root);
    let gitignore_content = read_gitignore(&repo_root);

    let stdin = io::stdin();
    let is_zero_sha = |sha: &str| sha.chars().all(|c| c == '0');

    let mut worst_exit_code = 0;
    let mut all_findings: Vec<Finding> = Vec::new();

    let options = ScanOptions {
        max_file_bytes: config.max_file_bytes.unwrap_or(5_000_000),
        disabled_rules: config.disable_rules.clone(),
        gitignore_content: gitignore_content.clone(),
    };

    for line_result in stdin.lock().lines() {
        let line = line_result?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let _local_ref = parts[0];
        let local_sha = parts[1];
        let _remote_ref = parts[2];
        let remote_sha = parts[3];

        // Skip deletion (all-zero local sha)
        if is_zero_sha(local_sha) {
            continue;
        }

        let diff = if is_zero_sha(remote_sha) {
            // New branch
            let commits = rev_list_not_remotes(local_sha)?;
            if commits.is_empty() {
                continue;
            }
            let oldest = match commits.last() {
                Some(c) => c,
                None => continue,
            };

            let base = match get_parent_commit(oldest) {
                Ok(parent) => parent,
                Err(_) => get_empty_tree_hash()?,
            };

            get_range_diff(&base, local_sha)?
        } else {
            get_range_diff(remote_sha, local_sha)?
        };

        let mut inputs = parse_unified_diff(&diff);
        for input in &mut inputs {
            input.size_bytes = get_file_size(&input.path, Some(local_sha));
        }

        for input in &inputs {
            all_findings.extend(scan_input(input, engine, &options));
        }
    }

    let decision = decide(all_findings, &baseline, &config.ignore);
    print_text_report(&decision, engine, false, &mut io::stderr())?;

    if decision.exit_code != 0 {
        worst_exit_code = decision.exit_code;
    }

    Ok(worst_exit_code)
}
