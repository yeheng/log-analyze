use chrono::{DateTime, Duration, Utc};

use crate::core::types::{Anomaly, AnomalyType, LogEntry, LogLevel};

/// Detect error-rate spikes using Z-score over fixed-size windows.
///
/// Splits the log timeline into windows of `window_secs` seconds, counts errors
/// per window, computes the Z-score of each window's error count against the
/// mean/stddev of all windows, and flags windows whose Z-score exceeds the
/// threshold.
pub fn detect_error_spikes(entries: &[LogEntry]) -> Vec<Anomaly> {
    if entries.is_empty() {
        return Vec::new();
    }

    let window_secs: i64 = 60;
    let z_threshold: f64 = 1.5;

    // Determine the time range.
    let min_ts = match entries.iter().filter_map(|e| e.timestamp).min() {
        Some(t) => t,
        None => return Vec::new(),
    };
    let max_ts = match entries.iter().filter_map(|e| e.timestamp).max() {
        Some(t) => t,
        None => return Vec::new(),
    };

    let total_secs = (max_ts - min_ts).num_seconds().max(1);
    let num_windows = ((total_secs / window_secs) + 1) as usize;
    if num_windows == 0 {
        return Vec::new();
    }

    // Count errors per window.
    let mut error_counts: Vec<u64> = vec![0; num_windows];
    let mut window_entries: Vec<u64> = vec![0; num_windows];

    for entry in entries {
        if let Some(ts) = entry.timestamp {
            let idx = ((ts - min_ts).num_seconds() / window_secs) as usize;
            if idx < num_windows {
                window_entries[idx] += 1;
                if matches!(entry.level, Some(LogLevel::Error)) {
                    error_counts[idx] += 1;
                }
            }
        }
    }

    // Compute mean and stddev of error counts.
    let n = error_counts.len() as f64;
    let mean: f64 = error_counts.iter().sum::<u64>() as f64 / n;
    let variance: f64 = error_counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();

    if stddev < f64::EPSILON {
        return Vec::new();
    }

    let mut anomalies = Vec::new();
    for (i, &count) in error_counts.iter().enumerate() {
        let z = (count as f64 - mean) / stddev;
        if z > z_threshold && count > 0 {
            let start = min_ts + Duration::seconds(i as i64 * window_secs);
            let end = start + Duration::seconds(window_secs);
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::Spike,
                start_time: Some(start),
                end_time: Some(end),
                score: z,
                detail: format!(
                    "Error spike: {} errors in {}s window (z-score={:.2})",
                    count, window_secs, z
                ),
            });
        }
    }

    anomalies
}

/// Detect time gaps larger than `gap_threshold_secs` between consecutive log entries.
pub fn detect_time_gaps(entries: &[LogEntry]) -> Vec<Anomaly> {
    let gap_threshold_secs: i64 = 10;

    let timestamps: Vec<DateTime<Utc>> = entries
        .iter()
        .filter_map(|e| e.timestamp)
        .collect();

    if timestamps.len() < 2 {
        return Vec::new();
    }

    let mut anomalies = Vec::new();
    for window in timestamps.windows(2) {
        let gap_secs = (window[1] - window[0]).num_seconds().abs();
        if gap_secs > gap_threshold_secs {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::Gap,
                start_time: Some(window[0]),
                end_time: Some(window[1]),
                score: gap_secs as f64,
                detail: format!(
                    "Time gap of {}s detected (threshold: {}s)",
                    gap_secs, gap_threshold_secs
                ),
            });
        }
    }

    anomalies
}
