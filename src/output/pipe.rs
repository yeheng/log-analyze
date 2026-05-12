use std::io::Write;

use anyhow::Result;

use crate::core::sink::Sink;
use crate::core::types::AnalysisReport;

pub struct PipeSink;

impl Sink for PipeSink {
    fn write(&self, report: &AnalysisReport) -> Result<()> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        // File info
        writeln!(out, "file_path\t{}", report.file_info.path)?;
        writeln!(out, "file_size\t{}", report.file_info.size_bytes)?;
        writeln!(out, "total_lines\t{}", report.file_info.total_lines)?;
        writeln!(out, "parse_errors\t{}", report.file_info.parse_errors)?;
        writeln!(out, "format\t{}", report.format.name)?;
        writeln!(out, "format_confidence\t{}", report.format.confidence)?;

        if let Some(ref tr) = report.time_range {
            writeln!(out, "time_start\t{}", tr.start)?;
            writeln!(out, "time_end\t{}", tr.end)?;
        }

        // Level distribution
        for (level, count) in &report.level_distribution {
            writeln!(out, "level_{}\t{}", format!("{:?}", level).to_lowercase(), count)?;
        }

        // Pattern matches
        for pm in &report.patterns {
            writeln!(out, "pattern\t{}\t{:?}\t{}\t{}", pm.pattern_name, pm.severity, pm.stats.count, pm.description)?;
        }

        // Anomalies
        for a in &report.anomalies {
            writeln!(out, "anomaly\t{:?}\t{:.2}\t{}", a.anomaly_type, a.score, a.detail)?;
        }

        out.flush()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "pipe"
    }
}
