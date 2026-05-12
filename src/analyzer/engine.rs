use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::analyzer::aggregator::Aggregator;
use crate::core::error::AppError;
use crate::core::pattern::Pattern;
use crate::core::types::{
    AnalysisReport, DetectedFormat, FileInfo, TimeRange,
};
use crate::parsers::Detector;

/// Detect log format using the full parser suite.
pub fn detect_format(path: &Path) -> Result<DetectedFormat, AppError> {
    let detector = Detector::new();
    let (format, _parser) = detector.detect(path)?;
    Ok(format)
}

/// Analyze a log file with the given patterns using streaming.
///
/// Detects the log format first, then streams lines through the
/// appropriate parser into the aggregator. No all_entries Vec —
/// memory-efficient.
pub fn analyze_file(
    path: &Path,
    patterns: Vec<Box<dyn Pattern>>,
    sample_lines: usize,
) -> Result<AnalysisReport, AppError> {
    let metadata = std::fs::metadata(path)?;
    let size_bytes = metadata.len();

    // Detect format and get the right parser.
    let detector = Detector::new();
    let (detected, parser) = detector.detect(path)?;

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut agg = Aggregator::new(patterns);

    for line in reader.lines() {
        let line = line?;
        let line_number = agg.total_lines() + 1 + agg.parse_errors();
        if let Some(entry) = parser.parse(line.as_bytes(), line_number) {
            agg.feed(entry);
        } else {
            agg.record_parse_error();
        }
    }

    // Collect results from aggregator.
    let stats_map = agg.build_stats();
    let mut samples = agg.take_samples();

    let mut anomalies = agg.take_anomalies();
    anomalies.extend(agg.detect_spikes());
    anomalies.extend(agg.detect_frequent(10));

    // Build PatternMatch list.
    let mut pattern_matches = Vec::new();
    let patterns_ref = agg.patterns();
    for pattern in patterns_ref {
        let name = pattern.name().to_string();
        if let Some(ms) = stats_map.get(&name) {
            if ms.count >= pattern.min_count() {
                let mut entries = samples.remove(&name).unwrap_or_default();
                entries.truncate(sample_lines);
                pattern_matches.push(pattern.build_match(entries, ms.clone()));
            }
        }
    }

    let time_range = match (agg.earliest(), agg.latest()) {
        (Some(start), Some(end)) => Some(TimeRange { start, end }),
        _ => None,
    };

    Ok(AnalysisReport {
        file_info: FileInfo {
            path: path.display().to_string(),
            size_bytes,
            total_lines: agg.total_lines(),
            parse_errors: agg.parse_errors(),
        },
        format: detected,
        time_range,
        level_distribution: agg.level_distribution().clone(),
        patterns: pattern_matches,
        anomalies,
    })
}
