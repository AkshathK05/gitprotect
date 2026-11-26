#![forbid(unsafe_code)]

pub mod decide;
pub mod engine;
pub mod entropy;
pub mod fingerprint;
pub mod masking;
pub mod rule;
pub mod types;

pub use decide::decide;
pub use engine::{
    LineIgnore, ScanOptions, gitignore_has_env_rule, parse_line_ignore, scan_input,
    should_skip_line_engine_for_path,
};
pub use entropy::{
    extract_quoted_literals, has_sensitive_keyword, is_uuid, scan_entropy, shannon_entropy,
};
pub use fingerprint::{collapse_whitespace, compute_fingerprint, normalize_path};
pub use masking::{mask_secret, mask_span, redaction_tag};
pub use rule::{
    CompiledLineRule, CompiledPathRule, RawRule, RuleEngine, RuleFile, RuleLoadError, RuleMetadata,
};
pub use types::{Decision, Finding, ScanInput, Severity};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_severity_ordering_and_serde() {
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Block);
        assert!(Severity::Info < Severity::Block);

        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(serde_json::to_string(&Severity::Warn).unwrap(), "\"warn\"");
        assert_eq!(
            serde_json::to_string(&Severity::Block).unwrap(),
            "\"block\""
        );
    }

    #[test]
    fn test_fingerprint_stability() {
        let fake_secret = format!("AKIA{}", "A".repeat(16));
        let fp1 = compute_fingerprint("SEC-001", "src/config/keys.rs", &fake_secret);
        let fp2 = compute_fingerprint("SEC-001", "src\\config\\keys.rs", &fake_secret);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
        assert!(
            fp1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn test_fingerprint_whitespace_collapsing() {
        let fake_secret_1 = "foo   \t\n  bar";
        let fake_secret_2 = "foo bar";
        let fp1 = compute_fingerprint("TEST-001", "foo/bar.txt", fake_secret_1);
        let fp2 = compute_fingerprint("TEST-001", "foo/bar.txt", fake_secret_2);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_secret_never_reaches_finding_or_json() {
        let fake_secret = format!("AKIA{}", "Z".repeat(16));
        let raw_line = format!("let aws_key = \"{}\";", fake_secret);
        let rule_id = "SEC-001";

        let masked_line = mask_secret(&raw_line, &fake_secret, rule_id);
        let fp = compute_fingerprint(rule_id, "aws.rs", &fake_secret);

        let finding = Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Block,
            path: normalize_path("aws.rs"),
            line: 42,
            masked_snippet: masked_line,
            fingerprint: fp,
        };

        assert!(!finding.masked_snippet.contains(&fake_secret));
        assert!(finding.masked_snippet.contains("[REDACTED_SEC-001]"));

        let serialized = serde_json::to_string(&finding).unwrap();
        assert!(!serialized.contains(&fake_secret));
        assert!(serialized.contains("[REDACTED_SEC-001]"));
    }

    #[test]
    fn test_decide_logic() {
        let fake_secret_1 = format!("AKIA{}", "1".repeat(16));
        let fake_secret_2 = format!("AKIA{}", "2".repeat(16));
        let fake_secret_3 = format!("AKIA{}", "3".repeat(16));

        let fp1 = compute_fingerprint("SEC-001", "a.rs", &fake_secret_1);
        let fp2 = compute_fingerprint("SEC-001", "b.rs", &fake_secret_2);
        let fp3 = compute_fingerprint("SEC-001", "c.rs", &fake_secret_3);

        let f1 = Finding {
            rule_id: "SEC-001".to_string(),
            severity: Severity::Block,
            path: "a.rs".to_string(),
            line: 1,
            masked_snippet: "[REDACTED_SEC-001]".to_string(),
            fingerprint: fp1.clone(),
        };

        let f2 = Finding {
            rule_id: "SEC-001".to_string(),
            severity: Severity::Block,
            path: "b.rs".to_string(),
            line: 2,
            masked_snippet: "[REDACTED_SEC-001]".to_string(),
            fingerprint: fp2.clone(),
        };

        let f3_warn = Finding {
            rule_id: "SEC-005".to_string(),
            severity: Severity::Warn,
            path: "c.rs".to_string(),
            line: 3,
            masked_snippet: "high entropy".to_string(),
            fingerprint: fp3.clone(),
        };

        let f1_duplicate = f1.clone();

        let mut baseline = HashSet::new();
        baseline.insert(fp1);

        let mut ignored = HashSet::new();
        ignored.insert(fp3);

        let findings = vec![f1, f1_duplicate, f2.clone(), f3_warn];
        let decision = decide(findings, &baseline, &ignored);

        assert_eq!(decision.exit_code, 1);
        assert_eq!(decision.blocking.len(), 1);
        assert_eq!(decision.blocking[0].fingerprint, f2.fingerprint);
        assert!(decision.warnings.is_empty());
        assert!(decision.info.is_empty());
    }

    #[test]
    fn test_invalid_regex_fails_not_panics() {
        let raw = RawRule {
            id: "TEST-INV".to_string(),
            severity: Severity::Block,
            kind: "line".to_string(),
            patterns: vec!["[invalid regex (".to_string()],
            globs: vec![],
            title: "Invalid".to_string(),
            what_happened: "Bad regex".to_string(),
            fix_steps: vec![],
            rotate_url: None,
            path_include: vec![],
            path_exclude: vec![],
        };

        let res = RuleEngine::compile(vec![raw]);
        assert!(res.is_err());
        let err = res.unwrap_err();
        match err {
            RuleLoadError::RegexError { rule_id, .. } => {
                assert!(rule_id == "TEST-INV" || rule_id == "regex_set");
            }
            _ => panic!("Expected RegexError"),
        }
    }

    // Per-rule tests: at least 2 positive and 2 negative tests each
    #[test]
    fn test_rule_sec_001_aws() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        let fake_aws_1 = format!("AKIA{}", "B".repeat(16));
        let fake_aws_2 = format!("AKIA{}", "C1D2E3F4G5H6I7J8");

        // Positive 1
        let input_pos1 = ScanInput {
            path: "src/aws.rs".to_string(),
            added_lines: vec![(10, format!("aws_key = \"{}\"", fake_aws_1))],
            size_bytes: None,
        };
        let findings_pos1 = scan_input(&input_pos1, &engine, &opts);
        assert_eq!(findings_pos1.len(), 1);
        assert_eq!(findings_pos1[0].rule_id, "SEC-001");
        assert_eq!(findings_pos1[0].severity, Severity::Block);

        // Positive 2
        let input_pos2 = ScanInput {
            path: "config.py".to_string(),
            added_lines: vec![(1, format!("AWS_SECRET = '{}'", fake_aws_2))],
            size_bytes: None,
        };
        let findings_pos2 = scan_input(&input_pos2, &engine, &opts);
        assert_eq!(findings_pos2.len(), 1);
        assert_eq!(findings_pos2[0].rule_id, "SEC-001");

        // Negative 1: too short
        let input_neg1 = ScanInput {
            path: "src/aws.rs".to_string(),
            added_lines: vec![(10, "let key = \"AKIA123\";".to_string())],
            size_bytes: None,
        };
        assert!(scan_input(&input_neg1, &engine, &opts).is_empty());

        // Negative 2: lower case characters in suffix
        let input_neg2 = ScanInput {
            path: "src/aws.rs".to_string(),
            added_lines: vec![(10, format!("let key = \"AKIA{}\";", "a".repeat(16)))],
            size_bytes: None,
        };
        assert!(scan_input(&input_neg2, &engine, &opts).is_empty());
    }

    #[test]
    fn test_rule_sec_001_openai_anthropic_google_stripe_razorpay_github_supabase() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // OpenAI Positive & Negative
        let fake_openai = format!("sk-proj-{}", "X".repeat(25));
        let res = scan_input(
            &ScanInput {
                path: "ai.js".to_string(),
                added_lines: vec![(1, format!("const key = \"{}\";", fake_openai))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].rule_id, "SEC-001");

        let res_neg = scan_input(
            &ScanInput {
                path: "ai.js".to_string(),
                added_lines: vec![(1, "const key = \"sk-proj-short\";".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_neg.is_empty());

        // Anthropic Positive & Negative
        let fake_ant = format!("sk-ant-{}", "Y".repeat(25));
        let res_ant = scan_input(
            &ScanInput {
                path: "ai.js".to_string(),
                added_lines: vec![(1, format!("const key = \"{}\";", fake_ant))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res_ant.len(), 1);
        assert_eq!(res_ant[0].rule_id, "SEC-001");

        let res_ant_neg = scan_input(
            &ScanInput {
                path: "ai.js".to_string(),
                added_lines: vec![(1, "const key = \"sk-ant-short\";".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_ant_neg.is_empty());

        // Google Positive & Negative
        let fake_google = format!("AIza{}", "G".repeat(35));
        let res_google = scan_input(
            &ScanInput {
                path: "g.ts".to_string(),
                added_lines: vec![(1, format!("key = \"{}\"", fake_google))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res_google.len(), 1);
        assert_eq!(res_google[0].rule_id, "SEC-001");

        let res_google_neg = scan_input(
            &ScanInput {
                path: "g.ts".to_string(),
                added_lines: vec![(1, "key = \"AIzaTooShort\"".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_google_neg.is_empty());

        // Stripe Positive & Negative
        let fake_stripe = format!("sk_live_{}", "S".repeat(20));
        let res_stripe = scan_input(
            &ScanInput {
                path: "stripe.ts".to_string(),
                added_lines: vec![(1, format!("key = \"{}\"", fake_stripe))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res_stripe.len(), 1);
        assert_eq!(res_stripe[0].rule_id, "SEC-001");

        let fake_stripe_test = format!("sk_test_{}", "T".repeat(20));
        let res_stripe_neg = scan_input(
            &ScanInput {
                path: "stripe.ts".to_string(),
                added_lines: vec![(1, format!("key = \"{}\"", fake_stripe_test))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_stripe_neg.is_empty());

        // Razorpay Positive & Negative
        let fake_razor = format!("rzp_live_{}", "R".repeat(12));
        let res_razor = scan_input(
            &ScanInput {
                path: "pay.ts".to_string(),
                added_lines: vec![(1, format!("key = \"{}\"", fake_razor))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res_razor.len(), 1);
        assert_eq!(res_razor[0].rule_id, "SEC-001");

        let fake_razor_test = format!("rzp_test_{}", "R".repeat(12));
        let res_razor_neg = scan_input(
            &ScanInput {
                path: "pay.ts".to_string(),
                added_lines: vec![(1, format!("key = \"{}\"", fake_razor_test))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_razor_neg.is_empty());

        // GitHub Positive & Negative
        let fake_gh = format!("ghp_{}", "H".repeat(36));
        let res_gh = scan_input(
            &ScanInput {
                path: "git.ts".to_string(),
                added_lines: vec![(1, format!("token = \"{}\"", fake_gh))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res_gh.len(), 1);
        assert_eq!(res_gh[0].rule_id, "SEC-001");

        let fake_gh_pat = format!("github_pat_{}", "P".repeat(22));
        let res_gh_pat = scan_input(
            &ScanInput {
                path: "git.ts".to_string(),
                added_lines: vec![(1, format!("token = \"{}\"", fake_gh_pat))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res_gh_pat.len(), 1);
        assert_eq!(res_gh_pat[0].rule_id, "SEC-001");

        let res_gh_neg = scan_input(
            &ScanInput {
                path: "git.ts".to_string(),
                added_lines: vec![(1, "token = \"ghp_too_short\"".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_gh_neg.is_empty());

        // Supabase Positive & Negative
        let fake_sb = format!("sbp_{}", &"0123456789abcdef".repeat(3)[..40]);
        let res_sb = scan_input(
            &ScanInput {
                path: "sb.ts".to_string(),
                added_lines: vec![(1, format!("token = \"{}\"", fake_sb))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(res_sb.len(), 1);
        assert_eq!(res_sb[0].rule_id, "SEC-001");

        let res_sb_neg = scan_input(
            &ScanInput {
                path: "sb.ts".to_string(),
                added_lines: vec![(1, "token = \"sbp_short\"".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_sb_neg.is_empty());
    }

    #[test]
    fn test_rule_sec_002() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1
        let pos1 = scan_input(
            &ScanInput {
                path: "frontend/config.ts".to_string(),
                added_lines: vec![(1, "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=xyz".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "SEC-002");

        // Positive 2
        let pos2 = scan_input(
            &ScanInput {
                path: "config.js".to_string(),
                added_lines: vec![(2, "export const key = VITE_ADMIN_PASSWORD;".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "SEC-002");

        // Negative 1: standard public var without secret keywords
        let neg1 = scan_input(
            &ScanInput {
                path: "config.js".to_string(),
                added_lines: vec![(1, "NEXT_PUBLIC_API_URL=https://api.example.com".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: internal server-only var without public prefix
        let neg2 = scan_input(
            &ScanInput {
                path: "server.js".to_string(),
                added_lines: vec![(1, "SERVER_ADMIN_PASSWORD=secret".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_sec_003() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: postgres with credentials
        let pos1 = scan_input(
            &ScanInput {
                path: "db.ts".to_string(),
                added_lines: vec![(
                    1,
                    "const url = \"postgres://admin:superSecretPass123@localhost:5432/mydb\";"
                        .to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "SEC-003");

        // Positive 2: mongodb+srv with credentials
        let pos2 = scan_input(
            &ScanInput {
                path: "db.ts".to_string(),
                added_lines: vec![(
                    1,
                    "url = \"mongodb+srv://root:pwd999@cluster0.abc.mongodb.net\";".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "SEC-003");

        // Negative 1: ${DB_PASSWORD} placeholder (explicitly required)
        let neg1 = scan_input(
            &ScanInput {
                path: "db.ts".to_string(),
                added_lines: vec![(
                    1,
                    "const url = `postgres://user:${DB_PASSWORD}@localhost:5432/mydb`;".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(
            neg1.is_empty(),
            "Must not match ${{DB_PASSWORD}} placeholder"
        );

        // Negative 2: $DB_PASSWORD placeholder (explicitly required)
        let neg2 = scan_input(
            &ScanInput {
                path: "db.ts".to_string(),
                added_lines: vec![(
                    1,
                    "const url = \"postgres://user:$DB_PASSWORD@localhost:5432/mydb\";".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty(), "Must not match $DB_PASSWORD placeholder");
    }

    #[test]
    fn test_rule_sec_004() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: RSA PRIVATE KEY
        let pos1 = scan_input(
            &ScanInput {
                path: "cert.pem".to_string(),
                added_lines: vec![(1, "-----BEGIN RSA PRIVATE KEY-----".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(pos1.iter().any(|f| f.rule_id == "SEC-004"));

        // Positive 2: EC PRIVATE KEY
        let pos2 = scan_input(
            &ScanInput {
                path: "key.txt".to_string(),
                added_lines: vec![(1, "-----BEGIN EC PRIVATE KEY-----".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "SEC-004");

        // Negative 1: PUBLIC KEY
        let neg1 = scan_input(
            &ScanInput {
                path: "pub.txt".to_string(),
                added_lines: vec![(1, "-----BEGIN PUBLIC KEY-----".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: CERTIFICATE
        let neg2 = scan_input(
            &ScanInput {
                path: "cert.txt".to_string(),
                added_lines: vec![(1, "-----BEGIN CERTIFICATE-----".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_sec_005_entropy() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: hex string with entropy > 3.0 near sensitive keyword
        // 32-char uniform hex has ~4.0 bits of entropy
        let hex_secret = "0123456789abcdef0123456789abcdef";
        let pos1 = scan_input(
            &ScanInput {
                path: "config.js".to_string(),
                added_lines: vec![(1, format!("const apiKey = \"{}\";", hex_secret))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "SEC-005");
        assert_eq!(pos1[0].severity, Severity::Warn);

        // Positive 2: non-hex high entropy string near sensitive keyword
        let random_secret = "aB3!dE7@gH9#jK1$mN3%pQ5^";
        let pos2 = scan_input(
            &ScanInput {
                path: "auth.py".to_string(),
                added_lines: vec![(1, format!("AUTH_TOKEN = '{}'", random_secret))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "SEC-005");

        // Negative 1: UUID (skipped)
        let neg_uuid = "123e4567-e89b-12d3-a456-426614174000";
        let neg1 = scan_input(
            &ScanInput {
                path: "user.js".to_string(),
                added_lines: vec![(1, format!("const user_token = \"{}\";", neg_uuid))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: URL containing :// (skipped)
        let neg2 = scan_input(
            &ScanInput {
                path: "auth.js".to_string(),
                added_lines: vec![(
                    1,
                    "const auth_url = \"https://example.com/oauth/v2/authorize/session\";"
                        .to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_file_001_path_globs_and_case_insensitivity() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positives
        let pos_files = vec![
            ".env",
            ".env.local",
            ".env.production",
            ".ENV",   // case-insensitive required
            "ID_RSA", // case-insensitive required
            "sub/dir/id_rsa",
            "server.pem",
            "cert.key",
            "id_ed25519",
            "firebase-adminsdk-abcd123.json",
            "credentials.json",
            "service-account-key.json",
        ];

        for p in pos_files {
            let res = scan_input(
                &ScanInput {
                    path: p.to_string(),
                    added_lines: vec![],
                    size_bytes: None,
                },
                &engine,
                &opts,
            );
            assert!(
                res.iter().any(|f| f.rule_id == "FILE-001"),
                "Expected FILE-001 for path: {p}"
            );
        }

        // Negatives (exceptions like .env.example, .env.sample, .env.template)
        let neg_files = vec![
            ".env.example",
            ".env.sample",
            ".env.template",
            "config/.env.example",
            "id_rsa.pub",
            "README.md",
            "app.js",
        ];

        for p in neg_files {
            let res = scan_input(
                &ScanInput {
                    path: p.to_string(),
                    added_lines: vec![],
                    size_bytes: None,
                },
                &engine,
                &opts,
            );
            assert!(
                !res.iter().any(|f| f.rule_id == "FILE-001"),
                "Did not expect FILE-001 for path: {p}"
            );
        }
    }

    #[test]
    fn test_rule_file_002_database_files() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: sqlite file (BLOCK)
        let pos1 = scan_input(
            &ScanInput {
                path: "data/dev.sqlite".to_string(),
                added_lines: vec![],
                size_bytes: Some(100),
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "FILE-002");
        assert_eq!(pos1[0].severity, Severity::Block);

        // Positive 2: backup.sql (WARN)
        let pos2 = scan_input(
            &ScanInput {
                path: "db/backup_2026.sql".to_string(),
                added_lines: vec![],
                size_bytes: Some(500),
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "FILE-002");
        assert_eq!(pos2[0].severity, Severity::Warn);

        // Positive 3: large .sql > 1_000_000 bytes (WARN)
        let pos3 = scan_input(
            &ScanInput {
                path: "db/seed.sql".to_string(),
                added_lines: vec![],
                size_bytes: Some(1_500_000),
            },
            &engine,
            &opts,
        );
        assert_eq!(pos3.len(), 1);
        assert_eq!(pos3[0].rule_id, "FILE-002");
        assert_eq!(pos3[0].severity, Severity::Warn);

        // Negative 1: normal small migration sql file
        let neg1 = scan_input(
            &ScanInput {
                path: "migrations/001_init.sql".to_string(),
                added_lines: vec![],
                size_bytes: Some(500),
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: regular rust file
        let neg2 = scan_input(
            &ScanInput {
                path: "src/db.rs".to_string(),
                added_lines: vec![],
                size_bytes: Some(200),
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_file_003_gitignore_env() {
        let engine = RuleEngine::load_embedded().unwrap();

        // Positive 1: .env staged without .gitignore having .env line
        let opts_missing = ScanOptions {
            gitignore_content: Some("node_modules/\ndist/\n".to_string()),
            ..Default::default()
        };
        let pos1 = scan_input(
            &ScanInput {
                path: ".env.example".to_string(),
                added_lines: vec![],
                size_bytes: None,
            },
            &engine,
            &opts_missing,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "FILE-003");
        assert_eq!(pos1[0].severity, Severity::Warn);

        // Positive 2: no gitignore content provided
        let opts_none = ScanOptions {
            gitignore_content: None,
            ..Default::default()
        };
        let pos2 = scan_input(
            &ScanInput {
                path: ".env.example".to_string(),
                added_lines: vec![],
                size_bytes: None,
            },
            &engine,
            &opts_none,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "FILE-003");

        // Negative 1: .gitignore has .env*
        let opts_ok = ScanOptions {
            gitignore_content: Some(".env*\nnode_modules/\n".to_string()),
            ..Default::default()
        };
        let neg1 = scan_input(
            &ScanInput {
                path: ".env.example".to_string(),
                added_lines: vec![],
                size_bytes: None,
            },
            &engine,
            &opts_ok,
        );
        assert!(neg1.is_empty());

        // Negative 2: staged file is not .env or .env.example
        let neg2 = scan_input(
            &ScanInput {
                path: "src/main.rs".to_string(),
                added_lines: vec![],
                size_bytes: None,
            },
            &engine,
            &opts_missing,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_file_004_max_file_size() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions {
            max_file_bytes: 5_000_000,
            ..Default::default()
        };

        // Positive 1: file size 6MB
        let pos1 = scan_input(
            &ScanInput {
                path: "assets/video.mp4".to_string(),
                added_lines: vec![],
                size_bytes: Some(6_000_000),
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "FILE-004");
        assert_eq!(pos1[0].severity, Severity::Warn);

        // Positive 2: file size 10MB
        let pos2 = scan_input(
            &ScanInput {
                path: "data/bundle.tar".to_string(),
                added_lines: vec![],
                size_bytes: Some(10_000_000),
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "FILE-004");

        // Negative 1: file size 1MB (< 5MB)
        let neg1 = scan_input(
            &ScanInput {
                path: "assets/small.png".to_string(),
                added_lines: vec![],
                size_bytes: Some(1_000_000),
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: no size_bytes specified
        let neg2 = scan_input(
            &ScanInput {
                path: "src/main.rs".to_string(),
                added_lines: vec![],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_baas_001() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: disable row level security
        let pos1 = scan_input(
            &ScanInput {
                path: "schema.sql".to_string(),
                added_lines: vec![(
                    1,
                    "ALTER TABLE users DISABLE ROW LEVEL SECURITY;".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "BAAS-001");
        assert_eq!(pos1[0].severity, Severity::Block);

        // Positive 2: create policy using (true)
        let pos2 = scan_input(
            &ScanInput {
                path: "migrations/rls.sql".to_string(),
                added_lines: vec![(
                    1,
                    "CREATE POLICY \"Public access\" ON posts FOR ALL USING (true);".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "BAAS-001");

        // Negative 1: enable row level security
        let neg1 = scan_input(
            &ScanInput {
                path: "schema.sql".to_string(),
                added_lines: vec![(
                    1,
                    "ALTER TABLE users ENABLE ROW LEVEL SECURITY;".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: create policy using auth.uid()
        let neg2 = scan_input(
            &ScanInput {
                path: "schema.sql".to_string(),
                added_lines: vec![(1, "CREATE POLICY \"User access\" ON posts FOR SELECT USING (auth.uid() = user_id);".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_baas_002() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: allow read: if true in firestore.rules
        let pos1 = scan_input(
            &ScanInput {
                path: "firestore.rules".to_string(),
                added_lines: vec![(1, "allow read, write: if true;".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "BAAS-002");
        assert_eq!(pos1[0].severity, Severity::Block);

        // Positive 2: request.auth == null in storage.rules
        let pos2 = scan_input(
            &ScanInput {
                path: "firebase/storage.rules".to_string(),
                added_lines: vec![(2, "allow read: if request.auth == null;".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "BAAS-002");

        // Negative 1: allow if request.auth != null
        let neg1 = scan_input(
            &ScanInput {
                path: "firestore.rules".to_string(),
                added_lines: vec![(1, "allow read, write: if request.auth != null;".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: same line in unrelated non-rules file
        let neg2 = scan_input(
            &ScanInput {
                path: "README.md".to_string(),
                added_lines: vec![(1, "allow read: if true;".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_baas_003() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: SUPABASE_SERVICE_ROLE_KEY in app/
        let pos1 = scan_input(
            &ScanInput {
                path: "app/dashboard/page.tsx".to_string(),
                added_lines: vec![(
                    1,
                    "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "BAAS-003");
        assert_eq!(pos1[0].severity, Severity::Warn);

        // Positive 2: firebase-admin in src/components/
        let pos2 = scan_input(
            &ScanInput {
                path: "src/components/Auth.tsx".to_string(),
                added_lines: vec![(1, "import admin from 'firebase-admin';".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "BAAS-003");

        // Negative 1: in api/ route (path_exclude)
        let neg1 = scan_input(
            &ScanInput {
                path: "app/api/admin/route.ts".to_string(),
                added_lines: vec![(
                    1,
                    "const key = process.env.SUPABASE_SERVICE_ROLE_KEY;".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: normal client key in components/
        let neg2 = scan_input(
            &ScanInput {
                path: "src/components/Auth.tsx".to_string(),
                added_lines: vec![(1, "const client = createClient(ANON_KEY);".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_code_003() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: eval(
        let pos1 = scan_input(
            &ScanInput {
                path: "app.js".to_string(),
                added_lines: vec![(1, "const res = eval(userInput);".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "CODE-003");
        assert_eq!(pos1[0].severity, Severity::Warn);

        // Positive 2: f-string SQL
        let pos2 = scan_input(
            &ScanInput {
                path: "query.py".to_string(),
                added_lines: vec![(
                    1,
                    "q = f\"SELECT * FROM users WHERE id = {user_id}\"".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "CODE-003");

        // Positive 3: template-literal SQL
        let pos3 = scan_input(
            &ScanInput {
                path: "db.js".to_string(),
                added_lines: vec![(
                    1,
                    "const q = `SELECT * FROM users WHERE id = ${id}`;".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos3.len(), 1);
        assert_eq!(pos3[0].rule_id, "CODE-003");

        // Negative 1: parameterized query
        let neg1 = scan_input(
            &ScanInput {
                path: "db.js".to_string(),
                added_lines: vec![(
                    1,
                    "db.query('SELECT * FROM users WHERE id = $1', [id]);".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: normal template string without SQL command
        let neg2 = scan_input(
            &ScanInput {
                path: "view.js".to_string(),
                added_lines: vec![(1, "const msg = `Hello ${username}!`;".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_rule_code_004() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();

        // Positive 1: verify=False in Python
        let pos1 = scan_input(
            &ScanInput {
                path: "fetch.py".to_string(),
                added_lines: vec![(1, "requests.get(url, verify = False)".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos1.len(), 1);
        assert_eq!(pos1[0].rule_id, "CODE-004");
        assert_eq!(pos1[0].severity, Severity::Warn);

        // Positive 2: rejectUnauthorized: false in Node
        let pos2 = scan_input(
            &ScanInput {
                path: "agent.js".to_string(),
                added_lines: vec![(
                    1,
                    "new https.Agent({ rejectUnauthorized: false });".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(pos2.len(), 1);
        assert_eq!(pos2[0].rule_id, "CODE-004");

        // Negative 1: verify=True
        let neg1 = scan_input(
            &ScanInput {
                path: "fetch.py".to_string(),
                added_lines: vec![(1, "requests.get(url, verify=True)".to_string())],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg1.is_empty());

        // Negative 2: rejectUnauthorized: true
        let neg2 = scan_input(
            &ScanInput {
                path: "agent.js".to_string(),
                added_lines: vec![(
                    1,
                    "new https.Agent({ rejectUnauthorized: true });".to_string(),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(neg2.is_empty());
    }

    #[test]
    fn test_line_engine_skips() {
        let engine = RuleEngine::load_embedded().unwrap();
        let opts = ScanOptions::default();
        let fake_key = format!("AKIA{}", "X".repeat(16));

        // Skip lockfiles
        for lockfile in &[
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Cargo.lock",
            "uv.lock",
            "poetry.lock",
            "sub/Cargo.lock",
        ] {
            let res = scan_input(
                &ScanInput {
                    path: lockfile.to_string(),
                    added_lines: vec![(1, format!("key = \"{}\"", fake_key))],
                    size_bytes: None,
                },
                &engine,
                &opts,
            );
            assert!(res.is_empty(), "Line engine must skip lockfile {lockfile}");
        }

        // Skip *.min.js
        let res_min = scan_input(
            &ScanInput {
                path: "bundle.min.js".to_string(),
                added_lines: vec![(1, format!("var k=\"{}\";", fake_key))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_min.is_empty(), "Line engine must skip *.min.js");

        // Skip .DS_Store
        let res_ds = scan_input(
            &ScanInput {
                path: ".DS_Store".to_string(),
                added_lines: vec![(1, format!("eval(\"{}\")", fake_key))],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(res_ds.is_empty(), "Line engine must skip .DS_Store");

        // Line-level gitprotect:ignore (bare)
        let res_bare_ignore = scan_input(
            &ScanInput {
                path: "src/keys.rs".to_string(),
                added_lines: vec![(
                    1,
                    format!("let key = \"{}\"; // gitprotect:ignore", fake_key),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(
            res_bare_ignore.is_empty(),
            "Bare gitprotect:ignore must ignore all findings on the line"
        );

        // Line-level gitprotect:ignore SEC-001 (specific rule ignored)
        let res_specific_ignore = scan_input(
            &ScanInput {
                path: "src/keys.rs".to_string(),
                added_lines: vec![(
                    1,
                    format!("let key = \"{}\"; // gitprotect:ignore SEC-001", fake_key),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert!(
            res_specific_ignore.is_empty(),
            "gitprotect:ignore SEC-001 must ignore SEC-001"
        );

        // Line-level gitprotect:ignore OTHER-RULE (does NOT ignore SEC-001)
        let res_other_ignore = scan_input(
            &ScanInput {
                path: "src/keys.rs".to_string(),
                added_lines: vec![(
                    1,
                    format!("let key = \"{}\"; // gitprotect:ignore SEC-002", fake_key),
                )],
                size_bytes: None,
            },
            &engine,
            &opts,
        );
        assert_eq!(
            res_other_ignore.len(),
            1,
            "gitprotect:ignore SEC-002 must NOT ignore SEC-001"
        );
        assert_eq!(res_other_ignore[0].rule_id, "SEC-001");
    }
}
