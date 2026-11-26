use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "gitprotect",
    version,
    about = "Security hook preventing leaked secrets and security mistakes for vibecoders"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install gitprotect hooks
    Init {
        /// Install hooks globally via core.hooksPath
        #[arg(long)]
        global: bool,

        /// Overwrite existing global core.hooksPath if already set
        #[arg(long)]
        force: bool,
    },

    /// Scan repository or staged files for security issues
    Scan {
        /// Scan only staged changes instead of whole working tree
        #[arg(long)]
        staged: bool,

        /// Output format (text or json)
        #[arg(long, default_value = "text")]
        format: FormatOption,

        /// Show verbose output including info-level findings
        #[arg(short, long)]
        verbose: bool,
    },

    /// Run hook handler (invoked by git hooks)
    Hook {
        /// Hook type: pre-commit or pre-push
        name: String,
    },

    /// Record all current findings to .gitprotect-baseline.json
    Baseline,

    /// Check health of gitprotect installation and git hooks
    Doctor,

    /// Remove gitprotect hooks and restore original hooks
    Uninstall {
        /// Uninstall global hooks and unset global core.hooksPath
        #[arg(long)]
        global: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum FormatOption {
    Text,
    Json,
}
