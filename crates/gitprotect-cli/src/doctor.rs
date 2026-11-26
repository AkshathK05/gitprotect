use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

use crate::git::{get_git_config, get_hooks_dir, run_git_cmd};

pub struct DoctorReport {
    pub all_passed: bool,
}

pub fn get_global_hooks_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config/gitprotect/hooks")
}

pub fn run_doctor() -> Result<DoctorReport> {
    let mut all_passed = true;

    println!("gitprotect doctor\n=================");

    // Check 1: git found
    match run_git_cmd(&["--version"], None) {
        Ok(v) => {
            println!("  [PASS] Git binary found: {}", v.trim());
        }
        Err(e) => {
            println!("  [FAIL] Git binary not found: {}", e);
            all_passed = false;
        }
    }

    // Check 2: Embedded binary path exists and is executable
    match std::env::current_exe() {
        Ok(exe) => {
            let canonical = fs::canonicalize(&exe).unwrap_or(exe);
            let metadata = fs::metadata(&canonical);
            let is_exec = match metadata {
                Ok(m) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        m.permissions().mode() & 0o111 != 0
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = m;
                        true
                    }
                }
                Err(_) => false,
            };

            if canonical.exists() && is_exec {
                println!(
                    "  [PASS] Native gitprotect binary is executable: {}",
                    canonical.display()
                );
            } else {
                println!(
                    "  [FAIL] Native gitprotect binary is missing or not executable: {}",
                    canonical.display()
                );
                all_passed = false;
            }
        }
        Err(e) => {
            println!("  [FAIL] Cannot determine current_exe: {}", e);
            all_passed = false;
        }
    }

    // Check 3: Global hooks status
    let _global_hooks_dir = get_global_hooks_dir();
    let global_config_hooks = get_git_config("core.hooksPath", true);
    let mut global_installed = false;

    if let Some(ref path_str) = global_config_hooks {
        let path = Path::new(path_str);
        let pre_commit = path.join("pre-commit");
        let pre_push = path.join("pre-push");
        if pre_commit.exists() && pre_push.exists() {
            println!(
                "  [PASS] Global hooks configured and present: {}",
                path.display()
            );
            global_installed = true;
        } else {
            println!(
                "  [FAIL] Global core.hooksPath set to '{}' but hook files are missing",
                path.display()
            );
            all_passed = false;
        }
    } else {
        println!("  [INFO] Global hooks not configured in git config --global core.hooksPath");
    }

    // Check 4: Local hooks in current repository
    match get_hooks_dir() {
        Ok(hooks_dir) => {
            let pre_commit = hooks_dir.join("pre-commit");
            let pre_push = hooks_dir.join("pre-push");

            let has_pre_commit = pre_commit.exists()
                && fs::read_to_string(&pre_commit)
                    .map(|c| c.contains("# Managed by gitprotect"))
                    .unwrap_or(false);
            let has_pre_push = pre_push.exists()
                && fs::read_to_string(&pre_push)
                    .map(|c| c.contains("# Managed by gitprotect"))
                    .unwrap_or(false);

            let mut hook_binary_valid = true;
            let managed_content = fs::read_to_string(&pre_commit)
                .ok()
                .filter(|c| c.contains("# Managed by gitprotect"));
            if let Some(content) = managed_content {
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("NATIVE_BIN=\"") {
                        let bin_path_str = rest.trim_end_matches('"');
                        let p = Path::new(bin_path_str);
                        if !p.exists() {
                            println!(
                                "  [FAIL] Hook embedded binary path does not exist: {}",
                                bin_path_str
                            );
                            hook_binary_valid = false;
                            all_passed = false;
                        }
                    }
                }
            }

            if has_pre_commit && has_pre_push && hook_binary_valid {
                println!(
                    "  [PASS] Repository hooks installed: {}",
                    hooks_dir.display()
                );
            } else if global_installed && hook_binary_valid {
                println!(
                    "  [INFO] Repository hooks not installed locally (using active global hooks)"
                );
            } else {
                println!(
                    "  [FAIL] Hooks not valid or installed in repository: {}",
                    hooks_dir.display()
                );
                all_passed = false;
            }

            // Check if local core.hooksPath overrides global
            if global_installed {
                let local_override = get_git_config("core.hooksPath", false);
                if let Some(local_path) = local_override {
                    let overrides_global = Some(&local_path) != global_config_hooks.as_ref();
                    if overrides_global {
                        println!(
                            "  [WARN] Local repository core.hooksPath '{}' overrides global hooksPath",
                            local_path
                        );
                    }
                }
            }
        }
        Err(_) => {
            println!("  [INFO] Not inside a git repository");
            if !global_installed {
                all_passed = false;
            }
        }
    }

    Ok(DoctorReport { all_passed })
}
