use assert_cmd::Command;
use std::fs;
use std::process::Command as StdCommand;
use tempfile::TempDir;

fn init_git_repo() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let path = dir.path();

    let run = |args: &[&str]| {
        let status = StdCommand::new("git")
            .args(args)
            .current_dir(path)
            .status()
            .expect("Failed to run git command");
        assert!(status.success(), "Git command failed: {:?}", args);
    };

    run(&["init"]);
    run(&["config", "user.name", "Test User"]);
    run(&["config", "user.email", "test@example.com"]);
    run(&["config", "commit.gpgsign", "false"]);

    dir
}

#[test]
fn test_commit_blocked_and_redacted() {
    let repo = init_git_repo();
    let fake_secret = format!("AKIA{}", "F".repeat(16));

    // Install gitprotect hooks
    let mut cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    cmd.current_dir(repo.path())
        .args(["init"])
        .assert()
        .success();

    // Stage file with fake secret
    let file_path = repo.path().join("aws_keys.rs");
    fs::write(&file_path, format!("let key = \"{}\";\n", fake_secret)).expect("write file");

    let status = StdCommand::new("git")
        .args(["add", "aws_keys.rs"])
        .current_dir(repo.path())
        .status()
        .expect("git add");
    assert!(status.success());

    // Run git commit - should fail
    let output = StdCommand::new("git")
        .args(["commit", "-m", "leaking key"])
        .current_dir(repo.path())
        .output()
        .expect("git commit");

    assert!(!output.status.success(), "Commit must be blocked by hook");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        combined.contains("[REDACTED_SEC-001]"),
        "Output must contain redaction tag: {combined}"
    );
    assert!(
        !combined.contains(&fake_secret),
        "Output must NOT contain raw secret!"
    );
}

#[test]
fn test_commit_clean_succeeds() {
    let repo = init_git_repo();

    let mut cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    cmd.current_dir(repo.path())
        .args(["init"])
        .assert()
        .success();

    let file_path = repo.path().join("clean.rs");
    fs::write(&file_path, "pub fn hello() -> &'static str { \"hello\" }\n").expect("write file");

    let status = StdCommand::new("git")
        .args(["add", "clean.rs"])
        .current_dir(repo.path())
        .status()
        .expect("git add");
    assert!(status.success());

    let output = StdCommand::new("git")
        .args(["commit", "-m", "clean commit"])
        .current_dir(repo.path())
        .output()
        .expect("git commit");

    assert!(
        output.status.success(),
        "Clean commit must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_baseline_suppresses_finding() {
    let repo = init_git_repo();
    let fake_secret = format!("AKIA{}", "B".repeat(16));

    let mut cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    cmd.current_dir(repo.path())
        .args(["init"])
        .assert()
        .success();

    let file_path = repo.path().join("aws.rs");
    fs::write(&file_path, format!("let key = \"{}\";\n", fake_secret)).expect("write file");

    let status = StdCommand::new("git")
        .args(["add", "aws.rs"])
        .current_dir(repo.path())
        .status()
        .expect("git add");
    assert!(status.success());

    // Record baseline
    let mut baseline_cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    baseline_cmd
        .current_dir(repo.path())
        .args(["baseline"])
        .assert()
        .success();

    assert!(repo.path().join(".gitprotect-baseline.json").exists());

    // Now commit should succeed because baseline suppresses it
    let output = StdCommand::new("git")
        .args(["commit", "-m", "commit with baseline"])
        .current_dir(repo.path())
        .output()
        .expect("git commit");

    assert!(
        output.status.success(),
        "Commit must succeed when finding is in baseline: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_doctor_fails_after_embedded_binary_invalid() {
    let repo = init_git_repo();

    let mut cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    cmd.current_dir(repo.path())
        .args(["init"])
        .assert()
        .success();

    // Invalidate embedded binary path in hook
    let pre_commit_path = repo.path().join(".git/hooks/pre-commit");
    let content = fs::read_to_string(&pre_commit_path).expect("read hook");
    let invalidated = content.replace("NATIVE_BIN=\"", "NATIVE_BIN=\"/nonexistent/bin/");
    fs::write(&pre_commit_path, invalidated).expect("write hook");

    let mut doctor_cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    doctor_cmd
        .current_dir(repo.path())
        .args(["doctor"])
        .assert()
        .failure();
}

#[test]
fn test_uninstall_restores_foreign_hook() {
    let repo = init_git_repo();
    let hooks_dir = repo.path().join(".git/hooks");
    fs::create_dir_all(&hooks_dir).expect("create hooks dir");

    let foreign_hook = "#!/bin/sh\necho 'custom foreign hook running'\nexit 0\n";
    let pre_commit_path = hooks_dir.join("pre-commit");
    fs::write(&pre_commit_path, foreign_hook).expect("write foreign hook");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&pre_commit_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&pre_commit_path, perms).unwrap();
    }

    // Run init: should backup foreign hook to pre-commit.gitprotect-orig
    let mut cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    cmd.current_dir(repo.path())
        .args(["init"])
        .assert()
        .success();

    let orig_path = hooks_dir.join("pre-commit.gitprotect-orig");
    assert!(orig_path.exists());
    assert_eq!(fs::read_to_string(&orig_path).unwrap(), foreign_hook);

    // Run uninstall: should restore pre-commit from pre-commit.gitprotect-orig
    let mut uninst = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    uninst
        .current_dir(repo.path())
        .args(["uninstall"])
        .assert()
        .success();

    assert!(!orig_path.exists());
    assert_eq!(fs::read_to_string(&pre_commit_path).unwrap(), foreign_hook);
}

#[test]
fn test_global_hooks_workflow() {
    let temp_home = TempDir::new().expect("temp home");
    let temp_gitconfig = temp_home.path().join(".gitconfig");

    let fake_secret = format!("AKIA{}", "G".repeat(16));

    // Global init
    let mut init_cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    init_cmd
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["init", "--global"])
        .assert()
        .success();

    // Verify global core.hooksPath set
    let global_hooks_dir = temp_home.path().join(".config/gitprotect/hooks");
    assert!(global_hooks_dir.join("pre-commit").exists());
    assert!(global_hooks_dir.join("pre-push").exists());

    // Refusal test: init --global refuses when a different hooksPath exists
    let _ = StdCommand::new("git")
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["config", "--global", "core.hooksPath", "/some/other/path"])
        .status();

    let mut refuse_cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    refuse_cmd
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["init", "--global"])
        .assert()
        .failure();

    // Force succeeds
    let mut force_cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    force_cmd
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["init", "--global", "--force"])
        .assert()
        .success();

    // Fresh repo without local hooks: commit with fake key blocked by global hook
    let repo = init_git_repo();
    let file_path = repo.path().join("secret.rs");
    fs::write(&file_path, format!("let key = \"{}\";\n", fake_secret)).expect("write");

    let _ = StdCommand::new("git")
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["add", "secret.rs"])
        .current_dir(repo.path())
        .status();

    let commit_res = StdCommand::new("git")
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["commit", "-m", "commit with global hook"])
        .current_dir(repo.path())
        .output()
        .expect("git commit");

    assert!(
        !commit_res.status.success(),
        "Global hook must block commit containing fake key"
    );

    // Repo's own pre-commit hook runs after gitprotect passes
    let sentinel = repo.path().join("hook_ran.sentinel");
    let local_hook_script = format!(
        "#!/bin/sh\ntouch \"{}\"\nexit 0\n",
        sentinel.to_string_lossy()
    );
    let local_hooks_dir = repo.path().join(".git/hooks");
    fs::create_dir_all(&local_hooks_dir).expect("create hooks");
    fs::write(local_hooks_dir.join("pre-commit"), local_hook_script).expect("write hook");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(local_hooks_dir.join("pre-commit"))
            .unwrap()
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(local_hooks_dir.join("pre-commit"), perms).unwrap();
    }

    // Clean commit through global hook
    fs::write(repo.path().join("safe.rs"), "let a = 10;\n").expect("write safe");
    let _ = StdCommand::new("git")
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["add", "safe.rs"])
        .current_dir(repo.path())
        .status();

    // Reset secret file so it doesn't block
    let _ = StdCommand::new("git")
        .args(["reset", "secret.rs"])
        .current_dir(repo.path())
        .status();
    let _ = fs::remove_file(repo.path().join("secret.rs"));

    let clean_res = StdCommand::new("git")
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .args(["commit", "-m", "clean commit chained"])
        .current_dir(repo.path())
        .output()
        .expect("git commit");

    assert!(
        clean_res.status.success(),
        "Clean commit with global hook chaining must succeed: {}",
        String::from_utf8_lossy(&clean_res.stderr)
    );
    assert!(
        sentinel.exists(),
        "Repository's own pre-commit hook must have run and created sentinel file"
    );

    // Doctor warns when a local core.hooksPath overrides global
    let _ = StdCommand::new("git")
        .args(["config", "core.hooksPath", ".git/custom-hooks"])
        .current_dir(repo.path())
        .status();

    let mut doc_cmd = Command::cargo_bin("gitprotect").expect("cargo_bin gitprotect");
    let doc_res = doc_cmd
        .env("HOME", temp_home.path())
        .env("GIT_CONFIG_GLOBAL", &temp_gitconfig)
        .current_dir(repo.path())
        .args(["doctor"])
        .assert()
        .success();

    let stdout_str = String::from_utf8_lossy(&doc_res.get_output().stdout);
    assert!(
        stdout_str.contains(".git/custom-hooks"),
        "Doctor must warn about local core.hooksPath override"
    );
}
