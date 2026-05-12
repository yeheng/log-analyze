use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "log-analyze", version, about = "A log analysis CLI tool for ops teams")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output format: terminal, json, pipe
    #[arg(short = 'f', long, global = true, default_value = "terminal")]
    pub format: Option<String>,

    /// Custom pattern rules file(s)
    #[arg(short = 'p', long, global = true)]
    pub patterns: Option<Vec<String>>,

    /// Output file path (for report command)
    #[arg(short = 'o', long, global = true)]
    pub output: Option<String>,

    /// Enable LLM-powered analysis
    #[arg(long, global = true)]
    pub llm: bool,

    /// Language for LLM output
    #[arg(long, global = true)]
    pub lang: Option<String>,

    /// Time range filter (e.g. "2026-01-01..2026-01-31")
    #[arg(long, global = true)]
    pub time_range: Option<String>,

    /// Minimum log level filter
    #[arg(long, global = true)]
    pub level: Option<String>,

    /// Detection rules files
    #[arg(long, global = true)]
    pub rules: Option<Vec<String>>,

    /// Number of threads
    #[arg(long, global = true)]
    pub threads: Option<usize>,

    /// Quiet mode (minimal output)
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Analyze a log file
    Analyze {
        /// Path to the log file
        path: String,

        /// Number of sample lines to show per pattern
        #[arg(short = 's', long, default_value = "10")]
        sample_lines: usize,
    },

    /// Detect the format of a log file
    Detect {
        /// Path to the log file
        path: String,
    },

    /// List available built-in patterns
    Patterns,

    /// Generate a report file
    Report {
        /// Path to the log file
        path: String,

        /// Number of sample lines to show per pattern
        #[arg(short = 's', long, default_value = "10")]
        sample_lines: usize,
    },
}
