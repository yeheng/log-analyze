use std::collections::HashMap;

use regex::Regex;

use crate::core::types::{Anomaly, AnomalyType, LogEntry};

/// Replace variable parts of a log message with placeholders to produce a
/// fingerprint that groups structurally similar messages.
pub fn fingerprint(message: &str) -> String {
    let s = replace_ips(message);
    let s = replace_uuids(&s);
    let s = replace_numbers(&s);
    s
}

fn replace_ips(s: &str) -> String {
    let re = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    re.replace_all(s, "<IP>").to_string()
}

fn replace_uuids(s: &str) -> String {
    let re = Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    re.replace_all(s, "<UUID>").to_string()
}

fn replace_numbers(s: &str) -> String {
    let re = Regex::new(r"\b\d{2,}\b").unwrap();
    re.replace_all(s, "<NUM>").to_string()
}

/// Produce a stable u64 hash of a fingerprint for efficient counting.
pub fn hash_fingerprint(fp: &str) -> u64 {
    // FNV-1a inspired hash -- fast, no external crate needed.
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in fp.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Detect the top-N most frequent log-message patterns.
///
/// Groups messages by fingerprint, counts occurrences, and returns anomalies
/// for patterns that appear frequently.
pub fn detect_frequent_patterns(entries: &[LogEntry], top_n: usize) -> Vec<Anomaly> {
    let mut counts: HashMap<String, u64> = HashMap::new();

    for entry in entries {
        let fp = fingerprint(&entry.message);
        *counts.entry(fp).or_insert(0) += 1;
    }

    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));

    let total = entries.len() as f64;

    ranked
        .into_iter()
        .take(top_n)
        .filter(|(_, count)| *count > 1)
        .map(|(fp, count)| Anomaly {
            anomaly_type: AnomalyType::Frequency,
            start_time: None,
            end_time: None,
            score: count as f64 / total,
            detail: format!(
                "Frequent pattern ({} occurrences, {:.1}%): {}",
                count,
                count as f64 / total * 100.0,
                truncate_str(&fp, 120)
            ),
        })
        .collect()
}

fn truncate_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}
