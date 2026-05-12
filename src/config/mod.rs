use serde::Deserialize;

use crate::core::error::AppError;

// ---------------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    #[cfg(feature = "llm")]
    pub llm: LlmConfig,
    pub detection: DetectionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub default_format: String,
    pub threads: usize,
    pub sample_lines: usize,
    pub quiet: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub enabled: bool,
    pub api_key: String,
    pub model: String,
    pub base_url: String,
    pub language: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    pub anomaly_threshold: f64,
    pub rules: Vec<String>,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

impl Default for Config {
    fn default() -> Self {
        Config {
            general: GeneralConfig::default(),
            #[cfg(feature = "llm")]
            llm: LlmConfig::default(),
            detection: DetectionConfig::default(),
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        GeneralConfig {
            default_format: String::from("auto"),
            threads: 4,
            sample_lines: 10,
            quiet: false,
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            enabled: false,
            api_key: String::new(),
            model: String::from("claude-sonnet-4-20250514"),
            base_url: String::from("https://api.anthropic.com"),
            language: String::from("en"),
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        DetectionConfig {
            anomaly_threshold: 2.0,
            rules: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Loading with multi-file merge
// ---------------------------------------------------------------------------

/// Config file search paths in ascending priority order.
fn config_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // /etc/log-analyze/config.toml
    paths.push(std::path::PathBuf::from("/etc/log-analyze/config.toml"));

    // ~/.config/log-analyze/config.toml
    if let Some(dir) = dirs_next::config_dir() {
        paths.push(dir.join("log-analyze").join("config.toml"));
    }

    // ./log-analyze.toml
    paths.push(std::path::PathBuf::from("log-analyze.toml"));

    paths
}

/// Load config by merging from lowest to highest priority files.
///
/// Merge strategy: **section-replace**, not field-merge.
/// A higher-priority file replaces an entire sub-section (e.g. `[general]`),
/// so any fields not specified in that section revert to their defaults.
///
/// Search paths (lowest → highest priority):
///   1. /etc/log-analyze/config.toml
///   2. ~/.config/log-analyze/config.toml
///   3. ./log-analyze.toml
pub fn load_config() -> Result<Config, AppError> {
    let mut config = Config::default();

    for path in config_paths() {
        if path.exists() {
            let content = std::fs::read_to_string(&path).map_err(|e| AppError::Config {
                path: path.display().to_string(),
                reason: format!("read error: {}", e),
            })?;
            let file_config: Config = toml::from_str(&content).map_err(|e| AppError::Config {
                path: path.display().to_string(),
                reason: format!("parse error: {}", e),
            })?;

            // Replace entire sub-sections from higher priority source
            config.general = file_config.general;
            #[cfg(feature = "llm")]
            {
                config.llm = file_config.llm;
            }
            config.detection = file_config.detection;
        }
    }

    Ok(config)
}

/// Apply CLI overrides on top of loaded config.
pub fn apply_overrides(config: &mut Config, cli: &crate::cli::Cli) {
    if cli.quiet {
        config.general.quiet = true;
    }
    if let Some(threads) = cli.threads {
        config.general.threads = threads;
    }
    if let Some(format) = &cli.format {
        config.general.default_format = format.clone();
    }
    if let Some(rules) = &cli.rules {
        config.detection.rules = rules.clone();
    }

    #[cfg(feature = "llm")]
    {
        if cli.llm {
            config.llm.enabled = true;
        }
        if let Some(ref lang) = cli.lang {
            config.llm.language = lang.clone();
        }
    }

    #[cfg(not(feature = "llm"))]
    {
        if cli.llm {
            eprintln!("Warning: --llm requires the 'llm' feature. Reinstall with --features llm.");
        }
    }
}
