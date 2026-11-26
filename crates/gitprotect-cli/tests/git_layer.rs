use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn init_temp_repo() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let path = dir.path();

    let run = |args: &[&str]| {
        let status = Command::new("git")
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
fn test_git_file_with_spaces_diff() {
    let repo = init_temp_repo();
    let file_path = repo.path().join("my secret file with spaces.txt");
    fs::write(&file_path, "TEST_DATA=hello\n").expect("write file");

    let status = Command::new("git")
        .args(["add", "my secret file with spaces.txt"])
        .current_dir(repo.path())
        .status()
        .expect("git add");
    assert!(status.success());

    let output = Command::new("git")
        .args([
            "-c",
            "core.quotepath=off",
            "diff",
            "--cached",
            "--unified=0",
            "--no-color",
            "--diff-filter=ACMR",
        ])
        .current_dir(repo.path())
        .output()
        .expect("git diff");

    let diff_str = String::from_utf8(output.stdout).expect("utf8");
    assert!(diff_str.contains("my secret file with spaces.txt"));
}

#[test]
fn test_git_empty_tree_hash_calculation() {
    let repo = init_temp_repo();

    let mut child = Command::new("git")
        .args(["hash-object", "-t", "tree", "--stdin"])
        .current_dir(repo.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("git hash-object spawn");

    // Feed empty stdin directly from Rust (no reliance on /dev/null)
    use std::io::Write;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"")
        .expect("write empty stdin");

    let output = child.wait_with_output().expect("wait_with_output");
    assert!(output.status.success());

    let hash = String::from_utf8(output.stdout)
        .expect("utf8")
        .trim()
        .to_string();
    assert_eq!(hash.len(), 40);
    assert_eq!(hash, "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
}

#[test]
fn test_git_root_commit_and_new_branch() {
    let repo = init_temp_repo();
    let file_path = repo.path().join("initial.txt");
    fs::write(&file_path, "initial content\n").expect("write file");

    Command::new("git")
        .args(["add", "initial.txt"])
        .current_dir(repo.path())
        .status()
        .expect("git add");

    Command::new("git")
        .args(["commit", "-m", "Initial root commit"])
        .current_dir(repo.path())
        .status()
        .expect("git commit");

    // Root commit has no parent: rev-parse <sha>^ fails
    let root_sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo.path())
        .output()
        .expect("rev-parse");
    let sha = String::from_utf8(root_sha.stdout)
        .expect("utf8")
        .trim()
        .to_string();

    let parent_check = Command::new("git")
        .args(["rev-parse", &format!("{sha}^")])
        .current_dir(repo.path())
        .output()
        .expect("rev-parse parent");
    assert!(
        !parent_check.status.success(),
        "Root commit must have no parent"
    );

    // In this root commit scenario, pre-push falls back to empty tree hash
    let empty_tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    let diff = Command::new("git")
        .args([
            "-c",
            "core.quotepath=off",
            "diff",
            "--unified=0",
            "--no-color",
            "--diff-filter=ACMR",
            empty_tree,
            &sha,
        ])
        .current_dir(repo.path())
        .output()
        .expect("diff against empty tree");

    let diff_str = String::from_utf8(diff.stdout).expect("utf8");
    assert!(diff_str.contains("initial.txt"));
}

#[test]
fn test_git_deleted_branch_detection() {
    let all_zeros = "0".repeat(40);
    let is_zero_sha = |sha: &str| sha.chars().all(|c| c == '0');
    assert!(is_zero_sha(&all_zeros));
    assert!(!is_zero_sha("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));
}
