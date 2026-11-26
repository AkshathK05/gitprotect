use gitprotect_core::ScanInput;

#[derive(Debug, Default)]
struct FileBuilder {
    path: Option<String>,
    is_deleted: bool,
    is_binary: bool,
    added_lines: Vec<(usize, String)>,
}

pub fn parse_unified_diff(diff_output: &str) -> Vec<ScanInput> {
    let mut results = Vec::new();
    let mut current_file: Option<FileBuilder> = None;
    let mut current_line = 0usize;

    for line in diff_output.lines() {
        if line.starts_with("diff --git ") {
            if let Some(FileBuilder {
                path: Some(path),
                is_deleted: false,
                is_binary: false,
                added_lines,
            }) = current_file.take()
            {
                results.push(ScanInput {
                    path,
                    added_lines,
                    size_bytes: None,
                });
            }
            current_file = Some(FileBuilder::default());
            current_line = 0;
            continue;
        }

        if let Some(ref mut fb) = current_file {
            if line.starts_with("Binary files ") {
                fb.is_binary = true;
                continue;
            }

            if line == "+++ /dev/null" {
                fb.is_deleted = true;
                continue;
            }

            if let Some(stripped) = line.strip_prefix("+++ b/") {
                fb.path = Some(stripped.to_string());
                continue;
            }

            if line.starts_with("@@ ") {
                if let Some(new_part) = line.split('+').nth(1) {
                    let num_str: String = new_part
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    current_line = num_str.parse::<usize>().unwrap_or(1);
                }
                continue;
            }

            if line.starts_with('+') && !line.starts_with("+++") {
                let content = &line[1..];
                fb.added_lines.push((current_line, content.to_string()));
                current_line += 1;
            } else if line.starts_with(' ') {
                current_line += 1;
            }
        }
    }

    if let Some(FileBuilder {
        path: Some(path),
        is_deleted: false,
        is_binary: false,
        added_lines,
    }) = current_file.take()
    {
        results.push(ScanInput {
            path,
            added_lines,
            size_bytes: None,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_diff() {
        let diff = r#"diff --git a/src/main.rs b/src/main.rs
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/main.rs
@@ -0,0 +1,2 @@
+fn main() {
+    println!("hello");
+}
"#;
        let inputs = parse_unified_diff(diff);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, "src/main.rs");
        assert_eq!(inputs[0].added_lines.len(), 3);
        assert_eq!(inputs[0].added_lines[0], (1, "fn main() {".to_string()));
        assert_eq!(
            inputs[0].added_lines[1],
            (2, "    println!(\"hello\");".to_string())
        );
        assert_eq!(inputs[0].added_lines[2], (3, "}".to_string()));
    }

    #[test]
    fn test_parse_diff_with_spaces_in_path() {
        let diff = r#"diff --git a/path with spaces/secret file.txt b/path with spaces/secret file.txt
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/path with spaces/secret file.txt
@@ -0,0 +1 @@
+SECRET_DATA=123
"#;
        let inputs = parse_unified_diff(diff);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, "path with spaces/secret file.txt");
        assert_eq!(inputs[0].added_lines.len(), 1);
        assert_eq!(inputs[0].added_lines[0], (1, "SECRET_DATA=123".to_string()));
    }

    #[test]
    fn test_parse_diff_ignores_deleted_and_binary() {
        let diff = r#"diff --git a/deleted.txt b/deleted.txt
deleted file mode 100644
index 1234567..0000000
--- a/deleted.txt
+++ /dev/null
@@ -1 +0,0 @@
-old content
diff --git a/image.png b/image.png
new file mode 100644
index 0000000..9999999
Binary files /dev/null and b/image.png differ
diff --git a/kept.txt b/kept.txt
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/kept.txt
@@ -0,0 +1 @@
+new content
"#;
        let inputs = parse_unified_diff(diff);
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, "kept.txt");
        assert_eq!(inputs[0].added_lines.len(), 1);
    }
}
