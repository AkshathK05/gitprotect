# gitprotect

**Stop leaked API keys and insecure configs before they reach GitHub.**

AI coding tools are fast, and sometimes they hardcode your Stripe key, commit your `.env`, or turn off Supabase Row Level Security. `gitprotect` is a Git hook that checks every commit and push and blocks the dangerous ones, so you can keep shipping fast.

- Works on **macOS, Linux and Windows**
- One native binary (written in Rust): fast, no runtime dependencies
- Never prints your secrets; matches are shown as `[REDACTED_SEC-001]`
- Never breaks your workflow because of its own bugs. If gitprotect itself fails, the commit goes through with a warning.

---

## Quick start

```bash
npm install -g @akshathk/gitprotect
cd your-project
gitprotect init
```

That's it. Every `git commit` and `git push` in this repo is now checked.

> **Beta:** while gitprotect is in beta, install with `npm install -g @akshathk/gitprotect@beta`.

To protect **every** repo on your machine at once:

```bash
gitprotect init --global
```

---

## What it catches

| Rule | Severity | What it catches |
|---|---|---|
| **SEC-001** | BLOCK | API keys for AWS, OpenAI, Anthropic, Google/Gemini/Firebase, Stripe, Razorpay, GitHub, Supabase |
| **SEC-002** | BLOCK | Secrets in public frontend env vars (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`), which get shipped to every visitor's browser |
| **SEC-003** | BLOCK | Database URLs with a password inside (`postgres://user:pass@host`). `${DB_PASSWORD}` style placeholders are fine. |
| **SEC-004** | BLOCK | Private keys (RSA, EC, OpenSSH) |
| **SEC-005** | WARN | Long random-looking strings next to words like `key`, `token`, `secret`, `password` |
| **FILE-001** | BLOCK | `.env` files, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, Firebase/GCP service account JSON (`.env.example` is allowed) |
| **FILE-002** | BLOCK / WARN | Database files (`*.sqlite`, `*.db`) block; SQL dumps/backups or SQL files over 1 MB warn |
| **FILE-003** | WARN | You're committing `.env` but `.gitignore` doesn't exclude it |
| **FILE-004** | WARN | Files over 5 MB |
| **BAAS-001** | BLOCK | Supabase/Postgres migrations that disable Row Level Security or create `USING (true)` policies |
| **BAAS-002** | BLOCK | Firebase rules open to everyone (`allow read, write: if true`) |
| **BAAS-003** | WARN | Admin SDKs or service-role keys used in frontend code |
| **CODE-003** | WARN | `eval()`, `child_process.exec()`, `shell=True`, `dangerouslySetInnerHTML`, SQL built with string formatting |
| **CODE-004** | WARN | Disabled TLS certificate checks (`verify=False`, `rejectUnauthorized: false`) |

**BLOCK** stops the commit. **WARN** shows the issue but lets the commit through.

---

## My commit was blocked. Now what?

gitprotect tells you the file, the line, what's wrong, and how to fix it. Usually the steps are:

1. **Move the secret out of your code** into a `.env` file, and make sure `.env` is in `.gitignore`.
2. **Read it at runtime** with `process.env.MY_KEY` (Node) or `os.environ["MY_KEY"]` (Python).
3. **Rotate the key** if it was ever pushed or shared. Assume a leaked key is compromised. Each finding includes a link to the provider's key page where available.
4. Commit again.

**It's a false positive?** Add a comment on that line:

```js
const example = "not-a-real-key-just-docs"; // gitprotect:ignore SEC-005
```

`gitprotect:ignore` alone skips all rules on that line; `gitprotect:ignore RULE-ID` skips just one.

**Need to commit right now anyway?** `git commit --no-verify` skips all hooks for one commit. Use it sparingly.

---

## Adding gitprotect to an existing project

Older projects may already have issues you can't fix today. Record them as a baseline so only **new** problems are blocked:

```bash
gitprotect baseline
git add .gitprotect-baseline.json
```

The baseline stores fingerprints only, never the secrets themselves, so it's safe to commit. Fingerprints ignore line numbers, so moving code around won't make old findings come back.

---

## Commands

| Command | What it does |
|---|---|
| `gitprotect init` | Install the pre-commit and pre-push hooks in this repo |
| `gitprotect init --global` | Install hooks for all repos (sets `core.hooksPath`; won't overwrite an existing one without `--force`) |
| `gitprotect scan --staged` | Check staged changes without committing |
| `gitprotect scan --staged --format json` | Same, as JSON (for CI or scripts) |
| `gitprotect baseline` | Accept current findings so only new ones are reported |
| `gitprotect doctor` | Check that hooks are installed and the binary works |
| `gitprotect uninstall` | Remove hooks from this repo (restores any hook you had before) |
| `gitprotect uninstall --global` | Remove the global hooks and unset `core.hooksPath` |

**Already using other Git hooks** (husky, lefthook, your own scripts)? gitprotect never overwrites them. It renames yours to `<hook>.gitprotect-orig` and runs it first.

---

## Configuration

Optional. Create `.gitprotect.toml` in your repo root:

```toml
# Turn off rules you don't want
disable_rules = ["FILE-004"]

# Ignore specific findings by fingerprint (shown in JSON scan output or baseline)
ignore = ["69ae07473172e28a"]

# Large-file warning threshold in bytes (default 5,000,000)
max_file_bytes = 10_000_000
```

---

## Platform notes

- **macOS:** Apple Silicon and Intel.
- **Linux:** x64 and arm64. Static binaries, work on any distro including Alpine.
- **Windows:** x64. Requires [Git for Windows](https://git-scm.com/download/win) (Git hooks run through its shell). Works from PowerShell, Git Bash, and VS Code.

The hooks call the native binary directly, not Node, so they also work in GUI Git apps that don't load your shell's `PATH`.

---

## Uninstalling

Remove the hooks **first**, then the package:

```bash
gitprotect uninstall            # in each repo where you ran init
gitprotect uninstall --global   # if you used --global
npm uninstall -g @akshathk/gitprotect
```

If you uninstall the package first, the leftover hooks print a warning and let commits through. Nothing breaks, but run `gitprotect uninstall` to clean up.

---

## Privacy

gitprotect runs entirely on your machine. It makes no network calls and sends no telemetry.

---

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
./scripts/build-npm.sh        # builds all 5 platform binaries and packs the npm packages
./scripts/test-npm-smoke.sh   # installs the packed tarballs and runs a real commit-block test
```

Releases are built and published by GitHub Actions (`.github/workflows/release.yml`) when a `v*` tag is pushed.

## License

MIT
