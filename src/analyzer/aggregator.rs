use std::collections::HashMap;
use std::collections::VecDeque;

use chrono::{DateTime, Duration, Utc};

use crate::core::pattern::Pattern;
use crate::core::types::{Anomaly, AnomalyType, LogEntry, LogLevel, MatchStats};
use crate::patterns::frequency;

const MAX_SAMPLES_PER_PATTERN: usize = 50;
const SPIKE_WINDOW_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// Per-pattern state (replaces four parallel HashMaps)
// ---------------------------------------------------------------------------

struct PatternState {
    count: u64,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    samples: Vec<LogEntry>,
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

pub struct Aggregator {
    patterns: Vec<Box<dyn Pattern>>,
    pattern_states: HashMap<String, PatternState>,

    // Level distribution.
    level_counts: HashMap<LogLevel, u64>,

    // Sliding window for spike detection (timestamps only, bounded).
    window: VecDeque<DateTime<Utc>>,
    window_error_count: u64,
    window_total_count: u64,

    // Fingerprint frequency tracking via hashed fingerprints.
    fingerprint_counts: HashMap<u64, u64>,
    fingerprint_strings: HashMap<u64, String>,

    // Gap detection.
    last_timestamp: Option<DateTime<Utc>>,

    // File-level stats.
    total_lines: u64,
    parse_errors: u64,
    earliest: Option<DateTime<Utc>>,
    latest: Option<DateTime<Utc>>,

    // Collected anomalies from streaming.
    anomalies: Vec<Anomaly>,
}

impl Aggregator {
    pub fn new(patterns: Vec<Box<dyn Pattern>>) -> Self {
        let mut pattern_states = HashMap::new();
        for p in &patterns {
            pattern_states.insert(p.name().to_string(), PatternState {
                count: 0,
                first_seen: None,
                last_seen: None,
                samples: Vec::new(),
            });
        }

        Self {
            patterns,
            pattern_states,
            level_counts: HashMap::new(),
            window: VecDeque::new(),
            window_error_count: 0,
            window_total_count: 0,
            fingerprint_counts: HashMap::new(),
            fingerprint_strings: HashMap::new(),
            last_timestamp: None,
            total_lines: 0,
            parse_errors: 0,
            earliest: None,
            latest: None,
            anomalies: Vec::new(),
        }
    }

    /// Feed a single parsed entry into the aggregator.
    pub fn feed(&mut self, entry: LogEntry) {
        self.total_lines += 1;

        // Update level distribution.
        if let Some(ref level) = entry.level {
            *self.level_counts.entry(level.clone()).or_insert(0) += 1;
        }

        // Update time range and detect gaps.
        if let Some(ts) = entry.timestamp {
            if self.earliest.map_or(true, |e| ts < e) {
                self.earliest = Some(ts);
            }
            if self.latest.map_or(true, |l| ts > l) {
                self.latest = Some(ts);
            }

            // Gap detection.
            if let Some(prev) = self.last_timestamp {
                let gap_secs = (ts - prev).num_seconds().abs();
                if gap_secs > 10 {
                    self.anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::Gap,
                        start_time: Some(prev),
                        end_time: Some(ts),
                        score: gap_secs as f64,
                        detail: format!(
                            "Time gap of {}s detected (threshold: 10s)",
                            gap_secs
                        ),
                    });
                }
            }
            self.last_timestamp = Some(ts);

            // Sliding window for spike detection.
            self.window.push_back(ts);
            self.window_total_count += 1;
            if matches!(entry.level, Some(LogLevel::Error)) {
                self.window_error_count += 1;
            }
            // Evict entries older than the window.
            let cutoff = ts - Duration::seconds(SPIKE_WINDOW_SECS);
            while let Some(&front) = self.window.front() {
                if front < cutoff {
                    self.window.pop_front();
                    self.window_total_count = self.window_total_count.saturating_sub(1);
                } else {
                    break;
                }
            }
        }

        // Fingerprint frequency.
        let fp = frequency::fingerprint(&entry.message);
        let h = frequency::hash_fingerprint(&fp);
        *self.fingerprint_counts.entry(h).or_insert(0) += 1;
        self.fingerprint_strings.entry(h).or_insert_with(|| fp.clone());

        // Pattern matching.
        let matched_names: Vec<String> = self.patterns
            .iter()
            .filter(|pattern| pattern.check(&entry))
            .map(|pattern| pattern.name().to_string())
            .collect();
        for name in matched_names {
            self.record_match(&name, &entry);
        }
    }

    /// Record a parse error (line that couldn't be parsed).
    pub fn record_parse_error(&mut self) {
        self.parse_errors += 1;
    }

    /// Increment pattern match stats and optionally sample the entry.
    fn record_match(&mut self, pattern_name: &str, entry: &LogEntry) {
        let state = self
            .pattern_states
            .entry(pattern_name.to_string())
            .or_insert_with(|| PatternState {
                count: 0,
                first_seen: None,
                last_seen: None,
                samples: Vec::new(),
            });

        state.count += 1;

        if state.first_seen.is_none() || entry.timestamp.map_or(false, |ts| Some(ts) < state.first_seen) {
            state.first_seen = entry.timestamp;
        }

        if entry.timestamp.map_or(true, |ts| Some(ts) >= state.last_seen) {
            state.last_seen = entry.timestamp;
        }

        if state.samples.len() < MAX_SAMPLES_PER_PATTERN {
            state.samples.push(entry.clone());
        }
    }

    /// Detect error-rate spikes from the streaming window.
    pub fn detect_spikes(&mut self) -> Vec<Anomaly> {
        if self.total_lines == 0 {
            return Vec::new();
        }

        let total_errors = self
            .level_counts
            .get(&LogLevel::Error)
            .copied()
            .unwrap_or(0);

        let overall_rate = total_errors as f64 / self.total_lines as f64;

        let mut spikes = Vec::new();
        if self.window_total_count > 0 && self.window_error_count > 3 {
            let window_rate = self.window_error_count as f64 / self.window_total_count as f64;
            if window_rate > overall_rate * 3.0 && overall_rate > 0.0 {
                let score = window_rate / overall_rate;
                spikes.push(Anomaly {
                    anomaly_type: AnomalyType::Spike,
                    start_time: self.window.front().copied(),
                    end_time: self.window.back().copied(),
                    score,
                    detail: format!(
                        "Error rate spike: {:.1}% in recent window vs {:.1}% overall",
                        window_rate * 100.0,
                        overall_rate * 100.0
                    ),
                });
            }
        }
        spikes
    }

    /// Detect frequent patterns from accumulated fingerprint counts.
    pub fn detect_frequent(&self, top_n: usize) -> Vec<Anomaly> {
        let mut ranked: Vec<_> = self.fingerprint_counts.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1));

        let total = self.total_lines as f64;

        ranked
            .into_iter()
            .take(top_n)
            .filter(|(_, &count)| count > 1)
            .map(|(hash, &count)| {
                let fp_str = self
                    .fingerprint_strings
                    .get(hash)
                    .cloned()
                    .unwrap_or_else(|| "<unknown>".to_string());
                Anomaly {
                    anomaly_type: AnomalyType::Frequency,
                    start_time: None,
                    end_time: None,
                    score: count as f64 / total,
                    detail: format!(
                        "Frequent pattern ({} occurrences, {:.1}%): {}",
                        count,
                        count as f64 / total * 100.0,
                        truncate_str(&fp_str, 120)
                    ),
                }
            })
            .collect()
    }

    /// Build per-pattern MatchStats.
    pub fn build_stats(&self) -> HashMap<String, MatchStats> {
        let mut stats = HashMap::new();
        for pattern in &self.patterns {
            let name = pattern.name().to_string();
            let state = self.pattern_states.get(&name);

            let count = state.map_or(0, |s| s.count);
            let first = state.and_then(|s| s.first_seen);
            let last = state.and_then(|s| s.last_seen);

            let rate_per_minute = if let (Some(f), Some(l)) = (first, last) {
                let secs = (l - f).num_seconds().max(1) as f64;
                count as f64 / (secs / 60.0)
            } else {
                0.0
            };

            stats.insert(
                name,
                MatchStats {
                    count,
                    first_seen: first,
                    last_seen: last,
                    rate_per_minute,
                },
            );
        }
        stats
    }

    /// Take all accumulated samples, leaving empty vectors behind.
    pub fn take_samples(&mut self) -> HashMap<String, Vec<LogEntry>> {
        let mut out = HashMap::new();
        for (name, state) in &mut self.pattern_states {
            out.insert(name.clone(), std::mem::take(&mut state.samples));
        }
        out
    }

    /// Total lines seen.
    pub fn total_lines(&self) -> u64 {
        self.total_lines
    }

    /// Parse errors seen.
    pub fn parse_errors(&self) -> u64 {
        self.parse_errors
    }

    /// Earliest timestamp.
    pub fn earliest(&self) -> Option<DateTime<Utc>> {
        self.earliest
    }

    /// Latest timestamp.
    pub fn latest(&self) -> Option<DateTime<Utc>> {
        self.latest
    }

    /// Level distribution.
    pub fn level_distribution(&self) -> &HashMap<LogLevel, u64> {
        &self.level_counts
    }

    /// Take all accumulated anomalies (gaps + spikes).
    pub fn take_anomalies(&mut self) -> Vec<Anomaly> {
        std::mem::take(&mut self.anomalies)
    }

    /// Get the pattern list reference.
    pub fn patterns(&self) -> &[Box<dyn Pattern>] {
        &self.patterns
    }
}

fn truncate_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        // Find a valid char boundary.
        let mut end = max_len;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        &s[..end]
    }
}
