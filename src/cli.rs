use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "apes", about = "Privilege elevation via OpenApe grants")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to config file
    #[arg(long, default_value = "/etc/apes/config.toml")]
    pub config: PathBuf,

    /// Poll timeout in seconds (overrides config)
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Human-readable reason for the grant request
    #[arg(long)]
    pub reason: Option<String>,

    /// Command and arguments to execute with elevated privileges
    #[arg(last = true)]
    pub cmd: Vec<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Enroll this machine as an OpenApe agent
    Enroll {
        /// OpenApe IdP URL
        #[arg(long)]
        server: String,

        /// Agent email address (used as identifier on the IdP)
        #[arg(long)]
        agent_email: String,

        /// Agent display name (defaults to hostname)
        #[arg(long)]
        agent_name: Option<String>,
    },
}
