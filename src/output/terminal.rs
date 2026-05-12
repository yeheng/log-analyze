use std::io::Write;

use colored::Colorize;
use anyhow::Result;

use crate::core::sink::Sink;
use crate::core::types::{AnalysisReport, LogLevel, Severity};

fn severity_color(s: &str, sev: Severity) -> colored::ColoredString {
    match sev {
        Severity::Critical => s.red().bold(),
        Severity::Warning => s.yellow(),
        Severity::Info => s.green(),
    }
}

fn level_color(s: &str, level: &LogLevel) -> colored::ColoredString {
    match level {
        LogLevel::Error => s.red().bold(),
        LogLevel::Warn => s.yellow(),
        LogLevel::Info => s.green(),
        LogLevel::Debug => s.white(),
        LogLevel::Trace => s.white().dimmed(),
    }
}

pub struct TerminalSink;

impl Sink for TerminalSink {
    fn write(&self, report: &AnalysisReport) -> Result<()> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        // File info header
        writeln!(out, "{}", "=== File Info ===".cyan().bold())?;
        writeln!(out, "  Path:          {}", report.file_info.path)?;
        writeln!(out, "  Size:          {} bytes", report.file_info.size_bytes)?;
        writeln!(out, "  Total lines:   {}", report.file_info.total_lines)?;
        writeln!(out, "  Parse errors:  {}", report.file_info.parse_errors)?;
        writeln!(out, "  Format:        {} (confidence {:.0}%)",
            report.format.name, report.format.confidence * 100.0)?;
        if let Some(ref tr) = report.time_range {
            writeln!(out, "  Time range:    {} -> {}", tr.start, tr.end)?;
        }
        writeln!(out)?;

        // Level distribution bar chart
        writeln!(out, "{}", "=== Level Distribution ===".cyan().bold())?;
        let total: u64 = report.level_distribution.values().sum();
        if total > 0 {
            let bar_width = 40usize;
            let levels = [
                LogLevel::Error,
                LogLevel::Warn,
                LogLevel::Info,
                LogLevel::Debug,
                LogLevel::Trace,
            ];
            for level in &levels {
                let count = report.level_distribution.get(level).copied().unwrap_or(0);
                let pct = count as f64 / total as f64;
                let filled = (pct * bar_width as f64).round() as usize;
                let bar: String = "#".repeat(filled) + &" ".repeat(bar_width - filled);
                let label = format!("{:>5}", format!("{:?}", level));
                writeln!(out, "  {} |{}| {:>6} ({:.1}%)",
                    level_color(&label, level),
                    level_color(&bar, level),
                    count,
                    pct * 100.0
                )?;
            }
        }
        writeln!(out)?;

        // Pattern matches with severity
        if !report.patterns.is_empty() {
            writeln!(out, "{}", "=== Pattern Matches ===".cyan().bold())?;
            for pm in &report.patterns {
                let sev_label = format!("[{:?}]", pm.severity);
                writeln!(out, "  {} {} ({})",
                    severity_color(&sev_label, pm.severity),
                    pm.pattern_name.bold(),
                    pm.description,
                )?;
                writeln!(out, "    Count: {}  Rate: {:.2}/min",
                    pm.stats.count, pm.stats.rate_per_minute)?;
                if let Some(first) = &pm.stats.first_seen {
                    writeln!(out, "    First: {}  Last: {}",
                        first,
                        pm.stats.last_seen.as_ref().map(|t| t.to_string()).unwrap_or_default()
                    )?;
                }
                // Show up to 5 sample entries
                for entry in pm.entries.iter().take(5) {
                    let msg = if entry.message.len() > 120 {
                        &entry.message[..entry.message.char_indices().take(120).last().map(|(i,c)| i + c.len_utf8()).unwrap_or(120)]
                    } else {
                        &entry.message
                    };
                    writeln!(out, "      L{}: {}", entry.line_number, msg)?;
                }
                if pm.entries.len() > 5 {
                    writeln!(out, "      ... and {} more", pm.entries.len() - 5)?;
                }
            }
            writeln!(out)?;
        }

        // Anomalies
        if !report.anomalies.is_empty() {
            writeln!(out, "{}", "=== Anomalies ===".cyan().bold())?;
            for a in &report.anomalies {
                let type_label = format!("[{:?}]", a.anomaly_type);
                writeln!(out, "  {} Score: {:.2} | {}",
                    type_label.yellow().bold(),
                    a.score,
                    a.detail,
                )?;
            }
            writeln!(out)?;
        }

        // Summary
        writeln!(out, "{}", "=== Summary ===".cyan().bold())?;
        writeln!(out, "  Patterns matched: {}", report.patterns.len())?;
        writeln!(out, "  Anomalies found:  {}", report.anomalies.len())?;
        let critical = report.patterns.iter()
            .filter(|p| matches!(p.severity, Severity::Critical))
            .count();
        let warnings = report.patterns.iter()
            .filter(|p| matches!(p.severity, Severity::Warning))
            .count();
        if critical > 0 {
            writeln!(out, "  {} critical pattern(s) detected", format!("{}", critical).red().bold())?;
        }
        if warnings > 0 {
            writeln!(out, "  {} warning pattern(s) detected", format!("{}", warnings).yellow())?;
        }
        if critical == 0 && warnings == 0 {
            writeln!(out, "  {}", "No critical issues found.".green())?;
        }

        out.flush()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "terminal"
    }
}
