use std::path::Path;

use clap::Parser;

use log_analyze::cli::{Cli, Commands};
use log_analyze::config;
use log_analyze::core::sink::Sink;
use log_analyze::output::terminal::TerminalSink;
use log_analyze::output::json::JsonSink;
use log_analyze::output::pipe::PipeSink;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config and apply CLI overrides
    let mut cfg = config::load_config().map_err(|e| anyhow::anyhow!("{}", e))?;
    config::apply_overrides(&mut cfg, &cli);

    match &cli.command {
        Commands::Analyze { path, sample_lines } => {
            analyze_command(&cli, &cfg, Path::new(path), *sample_lines)
        }
        Commands::Detect { path } => {
            detect_command(Path::new(path), &cfg)
        }
        Commands::Patterns => {
            patterns_command()
        }
        Commands::Report { path, sample_lines } => {
            report_command(&cli, &cfg, Path::new(path), *sample_lines)
        }
    }
}

fn get_sink(format: &str) -> Box<dyn Sink> {
    match format {
        "json" => Box::new(JsonSink),
        "pipe" => Box::new(PipeSink),
        _ => Box::new(TerminalSink),
    }
}

fn load_patterns_from_paths(
    paths: &[String],
) -> anyhow::Result<Vec<Box<dyn log_analyze::core::pattern::Pattern>>> {
    use log_analyze::patterns::custom::load_rules;

    let mut patterns = Vec::new();
    for path in paths {
        let custom = load_rules(Path::new(path))
            .map_err(|e| anyhow::anyhow!("Failed to load rules '{}': {}", path, e))?;
        patterns.extend(custom);
    }
    Ok(patterns)
}

fn collect_patterns(
    cli: &Cli,
    cfg: &config::Config,
) -> anyhow::Result<Vec<Box<dyn log_analyze::core::pattern::Pattern>>> {
    use log_analyze::patterns::builtin::all_builtin_patterns;

    let mut patterns = all_builtin_patterns();

    patterns.extend(load_patterns_from_paths(&cfg.detection.rules)?);
    if let Some(p) = &cli.patterns {
        patterns.extend(load_patterns_from_paths(p)?);
    }
    if let Some(r) = &cli.rules {
        patterns.extend(load_patterns_from_paths(r)?);
    }

    Ok(patterns)
}

fn run_analysis(
    cli: &Cli,
    cfg: &config::Config,
    path: &Path,
    sample_lines: usize,
) -> anyhow::Result<log_analyze::core::types::AnalysisReport> {
    let patterns = collect_patterns(cli, cfg)?;
    log_analyze::analyzer::engine::analyze_file(path, patterns, sample_lines)
        .map_err(|e| anyhow::anyhow!("{}", e))
}

fn analyze_command(
    cli: &Cli,
    cfg: &config::Config,
    path: &Path,
    sample_lines: usize,
) -> anyhow::Result<()> {
    let report = run_analysis(cli, cfg, path, sample_lines)?;

    let format = cli.format.as_deref().unwrap_or("terminal");
    let sink = get_sink(format);
    sink.write(&report)?;

    #[cfg(feature = "llm")]
    if cfg.llm.enabled {
        print_llm_analysis(&cfg.llm, &report)?;
    }

    Ok(())
}

fn detect_command(path: &Path, cfg: &config::Config) -> anyhow::Result<()> {
    let detected = log_analyze::analyzer::engine::detect_format(path)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if !cfg.general.quiet {
        println!("Detected format: {} (confidence: {:.0}%)",
            detected.name,
            detected.confidence * 100.0
        );
    }
    Ok(())
}

fn patterns_command() -> anyhow::Result<()> {
    use log_analyze::patterns::builtin::all_builtin_patterns;

    let patterns = all_builtin_patterns();
    println!("Available built-in patterns:\n");
    for p in &patterns {
        println!("  {} - {} [{:?}]",
            p.name(),
            p.description(),
            p.severity(),
        );
    }
    println!("\nTotal: {} patterns", patterns.len());
    Ok(())
}

fn report_command(
    cli: &Cli,
    cfg: &config::Config,
    path: &Path,
    sample_lines: usize,
) -> anyhow::Result<()> {
    let report = run_analysis(cli, cfg, path, sample_lines)?;

    let output_path = cli.output.as_deref().unwrap_or("report.txt");
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(output_path, json)?;
    println!("Report written to {}", output_path);

    #[cfg(feature = "llm")]
    if cfg.llm.enabled {
        print_llm_analysis(&cfg.llm, &report)?;
    }

    Ok(())
}

#[cfg(feature = "llm")]
fn print_llm_analysis(
    llm_config: &log_analyze::config::LlmConfig,
    report: &log_analyze::core::types::AnalysisReport,
) -> anyhow::Result<()> {
    use colored::Colorize;

    let report_json = serde_json::to_string_pretty(report)?;

    println!();
    println!("{}", "=== LLM Analysis ===".cyan().bold());
    println!("Asking {} (this may take a moment)...", llm_config.model);
    println!();

    match log_analyze::llm::analyze_with_llm(llm_config, &report_json) {
        Ok(response) => {
            println!("{}", response);
            println!();
        }
        Err(e) => {
            eprintln!("{} LLM analysis failed: {}", "Warning:".yellow().bold(), e);
            eprintln!("Rule-engine results above are still valid.");
        }
    }

    Ok(())
}
