use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn run_git_cmd(args: &[&str], input: Option<&[u8]>) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    if input.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let mut child = cmd.spawn().context("Failed to execute git process")?;

    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        let _ = stdin.write_all(data);
    }

    let output = child
        .wait_with_output()
        .context("Failed to wait on git process")?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git command failed ({:?}): {}", args, err_msg.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output is not valid utf-8")?;
    Ok(stdout)
}

pub fn get_repo_root() -> Result<PathBuf> {
    let out = run_git_cmd(&["rev-parse", "--show-toplevel"], None)?;
    Ok(PathBuf::from(out.trim()))
}

pub fn get_hooks_dir() -> Result<PathBuf> {
    let out = run_git_cmd(&["rev-parse", "--git-path", "hooks"], None)?;
    let p = PathBuf::from(out.trim());
    if p.is_absolute() {
        Ok(p)
    } else {
        let root = get_repo_root()?;
        Ok(root.join(p))
    }
}

pub fn get_cached_diff() -> Result<String> {
    run_git_cmd(
        &[
            "-c",
            "core.quotepath=off",
            "diff",
            "--cached",
            "--unified=0",
            "--no-color",
            "--diff-filter=ACMR",
        ],
        None,
    )
}

pub fn get_range_diff(base: &str, target: &str) -> Result<String> {
    run_git_cmd(
        &[
            "-c",
            "core.quotepath=off",
            "diff",
            "--unified=0",
            "--no-color",
            "--diff-filter=ACMR",
            base,
            target,
        ],
        None,
    )
}

pub fn get_file_size(path: &str, commit_ref: Option<&str>) -> Option<u64> {
    let target = match commit_ref {
        Some(r) => format!("{r}:{path}"),
        None => format!(":{path}"),
    };

    let out = run_git_cmd(&["cat-file", "-s", &target], None).ok()?;
    out.trim().parse::<u64>().ok()
}

pub fn get_empty_tree_hash() -> Result<String> {
    let out = run_git_cmd(&["hash-object", "-t", "tree", "--stdin"], Some(b""))?;
    Ok(out.trim().to_string())
}

pub fn rev_list_not_remotes(local_sha: &str) -> Result<Vec<String>> {
    let out = run_git_cmd(&["rev-list", local_sha, "--not", "--remotes"], None)?;
    let lines = out
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Ok(lines)
}

pub fn get_parent_commit(commit_sha: &str) -> Result<String> {
    let target = format!("{commit_sha}^");
    let out = run_git_cmd(&["rev-parse", &target], None)?;
    Ok(out.trim().to_string())
}

pub fn get_git_config(key: &str, global: bool) -> Option<String> {
    let mut args = vec!["config"];
    if global {
        args.push("--global");
    }
    args.push(key);

    run_git_cmd(&args, None)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn set_git_config_global(key: &str, value: &str) -> Result<()> {
    run_git_cmd(&["config", "--global", key, value], None)?;
    Ok(())
}

pub fn unset_git_config_global(key: &str) -> Result<()> {
    run_git_cmd(&["config", "--global", "--unset", key], None)?;
    Ok(())
}

pub fn read_gitignore(repo_root: &Path) -> Option<String> {
    let gitignore_path = repo_root.join(".gitignore");
    std::fs::read_to_string(gitignore_path).ok()
}
