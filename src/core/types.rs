use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum FieldValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub timestamp: Option<DateTime<Utc>>,
    pub level: Option<LogLevel>,
    pub source: Option<String>,
    pub message: String,
    pub fields: HashMap<String, FieldValue>,
    pub line_number: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MatchStats {
    pub count: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub rate_per_minute: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub severity: Severity,
    pub description: String,
    pub entries: Vec<LogEntry>,
    pub stats: MatchStats,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AnomalyType {
    Spike,
    Gap,
    Frequency,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Anomaly {
    pub anomaly_type: AnomalyType,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub score: f64,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size_bytes: u64,
    pub total_lines: u64,
    pub parse_errors: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetectedFormat {
    pub name: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisReport {
    pub file_info: FileInfo,
    pub format: DetectedFormat,
    pub time_range: Option<TimeRange>,
    pub level_distribution: HashMap<LogLevel, u64>,
    pub patterns: Vec<PatternMatch>,
    pub anomalies: Vec<Anomaly>,
}
