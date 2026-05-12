use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use log_analyze::core::types::{AnomalyType, LogEntry, LogLevel};
use log_analyze::patterns::anomaly::{detect_error_spikes, detect_time_gaps};

fn make_entry(message: &str, level: Option<LogLevel>, timestamp: Option<DateTime<Utc>>) -> LogEntry {
    LogEntry {
        timestamp,
        level,
        source: None,
        message: message.to_string(),
        fields: HashMap::new(),
        line_number: 0,
    }
}

fn ts(seconds_ago: i64) -> DateTime<Utc> {
    Utc::now() - Duration::seconds(seconds_ago)
}

#[test]
fn test_detect_error_spikes_basic() {
    // Create entries across several 60-second windows.
    // 6 windows with 1 error each, then 1 window with 50 errors (spike).
    let mut entries = Vec::new();

    // Window 0 (0-60s ago): 1 error
    entries.push(make_entry("error", Some(LogLevel::Error), Some(ts(10))));

    // Window 1 (60-120s ago): 50 errors (spike!)
    for _ in 0..50 {
        entries.push(make_entry("spike error", Some(LogLevel::Error), Some(ts(90))));
    }

    // Window 2 (120-180s ago): 1 error
    entries.push(make_entry("error", Some(LogLevel::Error), Some(ts(150))));

    // Window 3 (180-240s ago): 1 error
    entries.push(make_entry("error", Some(LogLevel::Error), Some(ts(210))));

    // Window 4 (240-300s ago): 1 error
    entries.push(make_entry("error", Some(LogLevel::Error), Some(ts(270))));

    // Window 5 (300-360s ago): 1 error
    entries.push(make_entry("error", Some(LogLevel::Error), Some(ts(330))));

    // Window 6 (360-420s ago): 1 error
    entries.push(make_entry("error", Some(LogLevel::Error), Some(ts(390))));

    let spikes = detect_error_spikes(&entries);
    // Should detect at least one spike
    assert!(!spikes.is_empty(), "Expected to detect error spikes");
    assert!(spikes.iter().all(|a| matches!(a.anomaly_type, AnomalyType::Spike)));
}

#[test]
fn test_detect_error_spikes_empty() {
    let entries: Vec<LogEntry> = Vec::new();
    let spikes = detect_error_spikes(&entries);
    assert!(spikes.is_empty());
}

#[test]
fn test_detect_error_spikes_no_timestamps() {
    let mut entries = Vec::new();
    for _ in 0..100 {
        entries.push(make_entry("error", Some(LogLevel::Error), None));
    }
    let spikes = detect_error_spikes(&entries);
    assert!(spikes.is_empty());
}

#[test]
fn test_detect_error_spikes_uniform() {
    // Uniform error distribution -- no spikes expected.
    let mut entries = Vec::new();
    for i in 0..5 {
        for _ in 0..2 {
            entries.push(make_entry(
                "error",
                Some(LogLevel::Error),
                Some(ts(i * 60 + 10)),
            ));
        }
    }
    let _spikes = detect_error_spikes(&entries);
    // Just check it doesn't panic.
}

#[test]
fn test_detect_time_gaps_basic() {
    let mut entries = Vec::new();

    // Continuous entries (1s apart)
    entries.push(make_entry("a", None, Some(ts(100))));
    entries.push(make_entry("b", None, Some(ts(99))));
    entries.push(make_entry("c", None, Some(ts(98))));

    // Big gap (18 seconds)
    entries.push(make_entry("d", None, Some(ts(80))));

    // Continuous again
    entries.push(make_entry("e", None, Some(ts(79))));
    entries.push(make_entry("f", None, Some(ts(78))));

    let gaps = detect_time_gaps(&entries);
    assert!(!gaps.is_empty(), "Expected to detect time gaps");
    assert!(gaps.iter().all(|a| matches!(a.anomaly_type, AnomalyType::Gap)));

    // Should find the gap between ts(98) and ts(80) = 18s
    let big_gap = gaps.iter().find(|a| a.score > 10.0);
    assert!(big_gap.is_some(), "Expected gap > 10s");
}

#[test]
fn test_detect_time_gaps_no_gaps() {
    let mut entries = Vec::new();
    // All entries 1 second apart -- no gaps > 10s
    for i in 0..10 {
        entries.push(make_entry("msg", None, Some(ts(100 - i))));
    }
    let gaps = detect_time_gaps(&entries);
    assert!(gaps.is_empty(), "Expected no gaps for continuous entries");
}

#[test]
fn test_detect_time_gaps_empty() {
    let entries: Vec<LogEntry> = Vec::new();
    let gaps = detect_time_gaps(&entries);
    assert!(gaps.is_empty());
}

#[test]
fn test_detect_time_gaps_single_entry() {
    let entries = vec![make_entry("msg", None, Some(ts(0)))];
    let gaps = detect_time_gaps(&entries);
    assert!(gaps.is_empty());
}
