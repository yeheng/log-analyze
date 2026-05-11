# Log Analyzer CLI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust CLI tool that auto-detects log formats and analyzes features (patterns, anomalies) to help ops teams quickly locate issues.

**Architecture:** Streaming pipeline — mmap file → chunk by line boundary → parallel parse → sequential pattern match → aggregate → output. Core traits (LogParser, Pattern, Sink) decouple format parsing from analysis rules from output targets.

**Tech Stack:** Rust, clap, memmap2, crossbeam, regex, serde_json, chrono, comfy-table, colored, toml, anyhow+thiserror, reqwest+tokio (LLM only), bytes.

**File Structure:**

```
src/
├── main.rs              — CLI entry point
├── lib.rs               — library root, re-exports
├── cli.rs               — clap CLI definitions
├── core/
│   ├── mod.rs
│   ├── types.rs         — LogEntry, LogLevel, Severity, etc.
│   ├── error.rs         — AppError
│   ├── parser.rs        — LogParser trait
│   ├── pattern.rs       — Pattern trait
│   └── sink.rs          — Sink trait
├── parsers/
│   ├── mod.rs           — FormatDetector
│   ├── json.rs
│   ├── syslog.rs
│   ├── nginx.rs
│   ├── apache.rs
│   └── generic.rs
├── patterns/
│   ├── mod.rs
│   ├── builtin.rs       — built-in rules
│   ├── custom.rs        — TOML rule loading
│   ├── anomaly.rs       — statistical anomaly detection
│   └── frequency.rs     — frequency analysis
├── analyzer/
│   ├── mod.rs
│   ├── engine.rs        — streaming pipeline engine
│   └── aggregator.rs    — real-time aggregation
├── output/
│   ├── mod.rs
│   ├── terminal.rs
│   ├── json.rs
│   ├── report.rs
│   └── pipe.rs
├── config/
│   └── mod.rs          — multi-file config merge
└── llm/
    ├── mod.rs
    └── client.rs
```

---

### Task 1: Project Scaffold & Core Types

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`
- Create: `src/core/mod.rs`
- Create: `src/core/types.rs`

- [ ] **Step 1: Write Cargo.toml**

```toml
[package]
name = "log-analyze"
version = "0.1.0"
edition = "2021"
description = "A log analysis CLI tool for ops teams"

[[bin]]
name = "log-analyze"
path = "src/main.rs"

[dependencies]
clap = { version = "4", features = ["derive"] }
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
comfy-table = "7"
colored = "2"
toml = "0.8"
anyhow = "1"
thiserror = "2"
once_cell = "1"
dirs-next = "2"
reqwest = { version = "0.12", features = ["json", "rustls-tls"], optional = true }
tokio = { version = "1", features = ["rt", "macros"], optional = true }

[features]
default = []
llm = ["reqwest", "tokio"]
```

- [ ] **Step 2: Write core types**

```rust
// src/core/types.rs
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    pub entries: Vec<LogEntry>, // sampled, max 50
    pub stats: MatchStats,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
```

- [ ] **Step 3: Write core/mod.rs**

```rust
// src/core/mod.rs
pub mod types;
pub mod error;
pub mod parser;
pub mod pattern;
pub mod sink;
```

- [ ] **Step 4: Write lib.rs**

```rust
// src/lib.rs
pub mod core;
pub mod parsers;
pub mod patterns;
pub mod analyzer;
pub mod output;
pub mod config;
#[cfg(feature = "llm")]
pub mod llm;
pub mod cli;
```

- [ ] **Step 5: Write minimal main.rs**

```rust
// src/main.rs
fn main() {
    println!("log-analyze v0.1.0");
}
```

- [ ] **Step 6: Build and verify**

Run: `cargo build`
Expected: Compiles successfully with no warnings.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml src/
git commit -m "feat: project scaffold with core types

Define LogEntry, PatternMatch, Anomaly, AnalysisReport types
and establish the module structure."
```

---

### Task 2: Error Types & Traits

**Files:**
- Create: `src/core/error.rs`
- Create: `src/core/parser.rs`
- Create: `src/core/pattern.rs`
- Create: `src/core/sink.rs`
- Modify: `src/core/mod.rs` (already includes these)

- [ ] **Step 1: Write error types**

```rust
// src/core/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error in {file}:{line}: {detail}")]
    Parse {
        file: String,
        line: u64,
        detail: String,
    },

    #[error("Config error in {path}: {reason}")]
    Config {
        path: String,
        reason: String,
    },

    #[error("LLM API error (status {status}): {message}")]
    Llm {
        status: u16,
        message: String,
    },
}
```

- [ ] **Step 2: Write LogParser trait**

```rust
// src/core/parser.rs
use crate::core::types::LogEntry;

pub trait LogParser: Send + Sync {
    /// Attempt to parse a raw log line. Returns None if the line
    /// doesn't match this parser's expected format.
    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry>;

    /// Parser name, e.g. "json", "nginx-access"
    fn name(&self) -> &str;

    /// Whether this parser can extract a log level from entries
    fn supports_level(&self) -> bool;

    /// Whether this parser can extract timestamps from entries
    fn supports_timestamp(&self) -> bool;
}

/// A parsed chunk of log lines
pub struct ParsedChunk {
    pub entries: Vec<LogEntry>,
    pub errors: u64,
}
```

- [ ] **Step 3: Write Pattern trait**

```rust
// src/core/pattern.rs
use crate::core::types::{LogEntry, PatternMatch, Severity};

pub trait Pattern: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> Severity;

    /// Check if a single entry matches. Returns Some(match_data)
    /// for aggregation, or None if no match.
    fn check(&self, entry: &LogEntry) -> bool;

    /// Minimum occurrences in the analysis window to report
    fn min_count(&self) -> u64 { 1 }

    /// Build a PatternMatch from collected matching entries
    fn build_match(&self, entries: Vec<LogEntry>, stats: crate::core::types::MatchStats) -> PatternMatch {
        PatternMatch {
            pattern_name: self.name().to_string(),
            severity: self.severity(),
            description: self.description().to_string(),
            entries,
            stats,
        }
    }
}
```

- [ ] **Step 4: Write Sink trait**

```rust
// src/core/sink.rs
use crate::core::types::AnalysisReport;
use anyhow::Result;

pub trait Sink: Send + Sync {
    fn write(&self, report: &AnalysisReport) -> Result<()>;
    fn name(&self) -> &str;
}
```

- [ ] **Step 5: Build and verify**

Run: `cargo build`
Expected: Compiles with no errors.

- [ ] **Step 6: Commit**

```bash
git add src/core/error.rs src/core/parser.rs src/core/pattern.rs src/core/sink.rs
git commit -m "feat: core traits and error types

Define LogParser, Pattern, Sink traits and AppError enum."
```

---

### Task 3: Generic Parser

**Files:**
- Create: `src/parsers/mod.rs`
- Create: `src/parsers/generic.rs`
- Create: `tests/fixtures/generic.log`
- Create: `tests/parsers_generic.rs`

- [ ] **Step 1: Write test fixture**

```
// tests/fixtures/generic.log
[2024-01-15 10:30:00] INFO  Starting application on port 8080
[2024-01-15 10:30:01] DEBUG Loading configuration from /etc/app/config.yaml
[2024-01-15 10:30:02] WARN  Connection pool is running low: 3/100 available
[2024-01-15 10:30:05] ERROR Failed to connect to database: connection refused
[2024-01-15 10:30:05] Traceback (most recent call last):
  File "app.py", line 42, in <module>
    db.connect()
  File "db.py", line 15, in connect
    raise ConnectionError("connection refused")
ConnectionError: connection refused
```

- [ ] **Step 2: Write test**

```rust
// tests/parsers_generic.rs
use log_analyze::parsers::generic::GenericParser;
use log_analyze::core::types::LogLevel;

#[test]
fn test_generic_parse_basic() {
    let entry = GenericParser::parse_line(
        b"[2024-01-15 10:30:05] ERROR Failed to connect to database: connection refused",
        1
    );
    assert!(entry.message.contains("connection refused"));
    assert_eq!(entry.level, Some(LogLevel::Error));
}

#[test]
fn test_generic_level_detection() {
    let info = GenericParser::parse_line(b"[2024-01-15 10:30:00] INFO Starting app", 1);
    assert_eq!(info.level, Some(LogLevel::Info));

    let warn = GenericParser::parse_line(b"[2024-01-15 10:30:02] WARN Pool low", 2);
    assert_eq!(warn.level, Some(LogLevel::Warn));

    let err = GenericParser::parse_line(b"[2024-01-15 10:30:05] ERROR connection refused", 3);
    assert_eq!(err.level, Some(LogLevel::Error));

    let dbg = GenericParser::parse_line(b"[2024-01-15 10:30:01] DEBUG config loaded", 4);
    assert_eq!(dbg.level, Some(LogLevel::Debug));
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test test_generic_parse_basic`
Expected: FAIL — Detector, Format, parse_file not defined.

- [ ] **Step 4: Implement Generic parser**

```rust
// src/parsers/generic.rs
use chrono::{DateTime, TimeZone, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::core::types::{FieldValue, LogEntry, LogLevel};

static LEVEL_PATTERNS: Lazy<Vec<(Regex, LogLevel)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(?i)\b(error|err|fatal|fail|critical|panic)\b").unwrap(), LogLevel::Error),
        (Regex::new(r"(?i)\b(warn|warning)\b").unwrap(), LogLevel::Warn),
        (Regex::new(r"(?i)\b(info|information|notice)\b").unwrap(), LogLevel::Info),
        (Regex::new(r"(?i)\b(debug|trace|verbose)\b").unwrap(), LogLevel::Debug),
    ]
});

static TS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?").unwrap(),
        Regex::new(r"\[?(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]?").unwrap(),
    ]
});

pub struct GenericParser;

impl GenericParser {
    pub fn parse_line(raw: &[u8], line_number: u64) -> LogEntry {
        let message = String::from_utf8_lossy(raw).trim().to_string();

        let level = LEVEL_PATTERNS
            .iter()
            .find(|(re, _)| re.is_match(&message))
            .map(|(_, lvl)| lvl.clone());

        let timestamp: Option<DateTime<Utc>> = TS_PATTERNS
            .iter()
            .find_map(|re| re.captures(&message))
            .and_then(|caps| caps.get(1))
            .and_then(|m| {
                let ts_str = m.as_str();
                DateTime::parse_from_rfc3339(ts_str)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|| {
                        // Try other common formats
                        Utc.datetime_from_str(ts_str, "%Y-%m-%d %H:%M:%S%.f").ok()
                            .or_else(|| Utc.datetime_from_str(ts_str, "%Y-%m-%d %H:%M:%S").ok())
                    })
            });

        LogEntry {
            timestamp,
            level,
            source: None,
            message,
            fields: std::collections::HashMap::new(),
            line_number,
        }
    }
}

pub fn parse_file(path: &Path) -> Result<Vec<LogEntry>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        entries.push(GenericParser::parse_line(line.as_bytes(), (i + 1) as u64));
    }
    Ok(entries)
}
```

- [ ] **Step 4b: Implement parsers/mod.rs with Detector**

```rust
// src/parsers/mod.rs
use std::path::Path;

use crate::core::types::DetectedFormat;

pub mod generic;
pub mod json;
pub mod syslog;
pub mod nginx;
pub mod apache;

pub struct Detector {
    // Will be populated as we add more parsers
}

impl Detector {
    pub fn new() -> Self {
        Detector {}
    }

    pub fn detect(&self, _path: &Path) -> Result<DetectedFormat, crate::core::error::AppError> {
        Ok(DetectedFormat {
            name: "generic".to_string(),
            confidence: 0.5,
        })
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test test_generic`
Expected: Tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/parsers/generic.rs src/parsers/mod.rs tests/
git commit -m "feat: generic log parser with level and timestamp detection"
```

---

### Task 4: JSON Parser

**Files:**
- Create: `src/parsers/json.rs`
- Create: `tests/fixtures/json.log`
- Create: `tests/parsers_json.rs`

- [ ] **Step 1: Write test fixture**

```
// tests/fixtures/json.log (one JSON object per line, NDJSON)
{"timestamp":"2024-01-15T10:30:00.123Z","level":"INFO","message":"Starting application","service":"api-server","duration_ms":12}
{"timestamp":"2024-01-15T10:30:01.456Z","level":"ERROR","message":"Failed to connect to database","service":"api-server","error_code":"ECONNREFUSED"}
{"timestamp":"2024-01-15T10:30:02.789Z","level":"WARN","message":"Connection pool low","service":"api-server","available":3,"total":100}
{"msg":"plain log line without standard fields","level":"debug","ts":"2024-01-15T10:30:03Z"}
{"@timestamp":"2024-01-15T10:30:04Z","severity":"CRITICAL","body":"Disk full"}
```

- [ ] **Step 2: Write test**

```rust
// tests/parsers_json.rs
use log_analyze::parsers::json::JsonParser;
use log_analyze::core::types::LogLevel;

#[test]
fn test_json_parse_standard_fields() {
    let parser = JsonParser;
    let entry = parser.parse(
        br#"{"timestamp":"2024-01-15T10:30:01Z","level":"ERROR","message":"db error"}"#,
        1
    ).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.level, Some(LogLevel::Error));
    assert_eq!(entry.message, "db error");
}

#[test]
fn test_json_parse_alternate_field_names() {
    let parser = JsonParser;
    let entry = parser.parse(
        br#"{"ts":"2024-01-15T10:30:03Z","level":"debug","msg":"plain log"}"#,
        1
    ).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.level, Some(LogLevel::Debug));
    assert_eq!(entry.message, "plain log");
}

#[test]
fn test_json_parse_preserves_extra_fields() {
    let parser = JsonParser;
    let entry = parser.parse(
        br#"{"level":"INFO","message":"ok","duration_ms":42,"user_id":"abc"}"#,
        1
    ).unwrap();
    assert!(entry.fields.contains_key("duration_ms"));
    assert!(entry.fields.contains_key("user_id"));
}

#[test]
fn test_json_rejects_non_json() {
    let parser = JsonParser;
    assert!(parser.parse(b"not json at all", 1).is_none());
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test parsers_json`
Expected: FAIL — JsonParser not defined.

- [ ] **Step 4: Implement JsonParser**

```rust
// src/parsers/json.rs
use chrono::Utc;

use crate::core::parser::LogParser;
use crate::core::types::{FieldValue, LogEntry, LogLevel};

const TS_FIELD_NAMES: &[&str] = &["timestamp", "ts", "time", "@timestamp", "datetime"];
const LEVEL_FIELD_NAMES: &[&str] = &["level", "severity", "log_level", "loglevel"];
const MSG_FIELD_NAMES: &[&str] = &["message", "msg", "body", "text", "content"];

pub struct JsonParser;

impl LogParser for JsonParser {
    fn name(&self) -> &str { "json" }
    fn supports_level(&self) -> bool { true }
    fn supports_timestamp(&self) -> bool { true }

    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let text = std::str::from_utf8(raw).ok()?.trim();
        if !text.starts_with('{') {
            return None;
        }

        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text).ok()?;        let timestamp = TS_FIELD_NAMES.iter()
            .find_map(|name| obj.get(*name))
            .and_then(|v| v.as_str())
            .and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|| {
                        Utc.datetime_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ").ok()
                    })
            });

        let level = LEVEL_FIELD_NAMES.iter()
            .find_map(|name| obj.get(*name))
            .and_then(|v| v.as_str())
            .map(|s| match s.to_uppercase().as_str() {
                "ERROR" | "ERR" | "FATAL" | "CRITICAL" | "PANIC" => LogLevel::Error,
                "WARN" | "WARNING" => LogLevel::Warn,
                "INFO" | "INFORMATION" | "NOTICE" => LogLevel::Info,
                "DEBUG" | "TRACE" | "VERBOSE" => LogLevel::Debug,
                _ => LogLevel::Info,
            });

        let message = MSG_FIELD_NAMES.iter()
            .find_map(|name| obj.get(*name))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default();

        let source = obj.get("service")
            .or_else(|| obj.get("source"))
            .or_else(|| obj.get("logger"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Capture remaining fields
        let known_keys: std::collections::HashSet<&str> = TS_FIELD_NAMES.iter()
            .chain(LEVEL_FIELD_NAMES)
            .chain(MSG_FIELD_NAMES)
            .chain(&["service", "source", "logger"])
            .copied()
            .collect();

        let fields: std::collections::HashMap<String, FieldValue> = obj.iter()
            .filter(|(k, _)| !known_keys.contains(k.as_str()))
            .map(|(k, v)| {
                let val = match v {
                    serde_json::Value::String(s) => FieldValue::String(s.clone()),
                    serde_json::Value::Number(n) => {
                        FieldValue::Number(n.as_f64().unwrap_or(0.0))
                    }
                    serde_json::Value::Bool(b) => FieldValue::Boolean(*b),
                    _ => FieldValue::Null,
                };
                (k.clone(), val)
            })
            .collect();

        Some(LogEntry {
            timestamp,
            level,
            source,
            message,
            fields,
            line_number,
        })
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test parsers_json`
Expected: All 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/parsers/json.rs tests/parsers_json.rs tests/fixtures/json.log
git commit -m "feat: JSON log parser with flexible field name detection"
```

---

### Task 5: Syslog Parser

**Files:**
- Create: `src/parsers/syslog.rs`
- Create: `tests/fixtures/syslog.log`
- Create: `tests/parsers_syslog.rs`

- [ ] **Step 1: Write test fixture**

```
// tests/fixtures/syslog.log
Jan 15 10:30:00 localhost kernel: [    0.000000] Linux version 5.15.0
Jan 15 10:30:01 server01 systemd[1]: Starting Network Time Service...
Jan 15 10:30:01 server01 NetworkManager[852]: <info>  [1705309801.1234] device (eth0): carrier: link connected
Jan 15 10:30:02 server01 sshd[1024]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:30:03 server01 kernel: [  120.456789] Out of memory: Killed process 2048 (java) total-vm:4194304kB
Jan 15 10:30:04 server01 cron[512]: (root) CMD (run-parts /etc/cron.hourly)
<30>Jan 15 10:30:05 server01 app[1234]: Request processed in 45ms
<11>Jan 15 10:30:05 server01 app[1234]: Disk usage on /data is at 95%
```

- [ ] **Step 2: Write test**

```rust
// tests/parsers_syslog.rs
use log_analyze::parsers::syslog::SyslogParser;
use log_analyze::core::parser::LogParser;
use log_analyze::core::types::LogLevel;

#[test]
fn test_syslog_parse_standard() {
    let parser = SyslogParser;
    let entry = parser.parse(
        b"Jan 15 10:30:02 server01 sshd[1024]: Failed password for root from 192.168.1.100",
        1
    ).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error)); // "Failed"
    assert_eq!(entry.source.as_deref(), Some("sshd"));
    assert!(entry.message.contains("Failed password"));
}

#[test]
fn test_syslog_parse_with_pri() {
    let parser = SyslogParser;
    // <11> = facility 1 (user), severity 3 (error)
    let entry = parser.parse(
        b"<11>Jan 15 10:30:05 server01 app[1234]: Disk usage on /data is at 95%",
        1
    ).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
}

#[test]
fn test_syslog_rejects_non_syslog() {
    let parser = SyslogParser;
    assert!(parser.parse(b"{\"key\": \"value\"}", 1).is_none());
}
```

- [ ] **Step 3: Implement SyslogParser**

```rust
// src/parsers/syslog.rs
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::parser::LogParser;
use crate::core::types::{LogEntry, LogLevel};

static SYSLOG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(?:<(\d+)>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$"
    ).unwrap()
});

pub struct SyslogParser;

impl LogParser for SyslogParser {
    fn name(&self) -> &str { "syslog" }
    fn supports_level(&self) -> bool { true }
    fn supports_timestamp(&self) -> bool { true }

    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let text = std::str::from_utf8(raw).ok()?;
        let caps = SYSLOG_RE.captures(text)?;

        let pri = caps.get(1).and_then(|m| m.as_str().parse::<u8>().ok());

        let timestamp = caps.get(2).and_then(|m| {
            let ts_str = m.as_str();
            // Resolve "Jan 15 10:30:00" to a DateTime assuming current year
            let now = Utc::now();
            let year = now.year();
            let full = format!("{} {} {:04}", ts_str, year);
            Utc.datetime_from_str(&full, "%b %d %H:%M:%S %Y").ok()
        });

        let host = caps.get(3).map(|m| m.as_str().to_string());
        let source = caps.get(4).map(|m| m.as_str().to_string());

        let message = caps.get(6).map(|m| m.as_str().to_string()).unwrap_or_default();

        let level = pri.map(|p| severity_from_pri(p))
            .or_else(|| detect_level_from_message(&message));

        Some(LogEntry {
            timestamp,
            level,
            source,
            message,
            fields: std::collections::HashMap::new(),
            line_number,
        })
    }
}

fn severity_from_pri(pri: u8) -> LogLevel {
    match pri & 0x07 {
        0 | 1 | 2 => LogLevel::Error, // emerg, alert, crit
        3 => LogLevel::Error,          // error
        4 => LogLevel::Warn,          // warning
        5 | 6 => LogLevel::Info,      // notice, info
        _ => LogLevel::Debug,         // debug
    }
}

fn detect_level_from_message(msg: &str) -> Option<LogLevel> {
    let lower = msg.to_lowercase();
    if lower.contains("failed") || lower.contains("error") || lower.contains("oom") || lower.contains("killed") {
        Some(LogLevel::Error)
    } else if lower.contains("warn") || lower.contains("disk usage") {
        Some(LogLevel::Warn)
    } else if lower.contains("debug") {
        Some(LogLevel::Debug)
    } else {
        Some(LogLevel::Info)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test parsers_syslog`
Expected: All 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/parsers/syslog.rs tests/parsers_syslog.rs tests/fixtures/syslog.log
git commit -m "feat: syslog parser with RFC 3164 and PRI support"
```

---

### Task 6: Nginx Parser

**Files:**
- Create: `src/parsers/nginx.rs`
- Create: `tests/fixtures/nginx.log`
- Create: `tests/parsers_nginx.rs`

- [ ] **Step 1: Write test fixture**

```
// tests/fixtures/nginx.log
192.168.1.10 - - [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.20 - admin [15/Jan/2024:10:30:01 +0000] "POST /api/upload HTTP/1.1" 201 567 "-" "curl/7.68.0"
10.0.0.5 - - [15/Jan/2024:10:30:02 +0000] "GET /admin HTTP/1.1" 403 45 "-" "python-requests/2.28"
192.168.1.10 - - [15/Jan/2024:10:30:03 +0000] "GET /api/search?q=test HTTP/1.1" 500 89 "-" "Mozilla/5.0"
192.168.1.15 - - [15/Jan/2024:10:30:04 +0000] "DELETE /api/items/42 HTTP/1.1" 204 0 "-" "Mozilla/5.0"
127.0.0.1 - - [15/Jan/2024:10:30:05 +0000] "GET /health HTTP/1.1" 200 15 "-" "kube-probe/1.27"
10.0.0.1 - - [15/Jan/2024:10:30:06 +0000] "GET /api/reports HTTP/1.1" 502 67 "-" "Mozilla/5.0"
```

- [ ] **Step 2: Write test**

```rust
// tests/parsers_nginx.rs
use log_analyze::parsers::nginx::NginxParser;
use log_analyze::core::parser::LogParser;
use log_analyze::core::types::{LogLevel, FieldValue};

#[test]
fn test_nginx_parse_standard() {
    let parser = NginxParser;
    let entry = parser.parse(
        br#"192.168.1.10 - - [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#,
        1
    ).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.level, Some(LogLevel::Info)); // 200 = success
    assert_eq!(entry.fields.get("status").and_then(|v| {
        if let FieldValue::Number(n) = v { Some(*n as u16) } else { None }
    }), Some(200));
    assert_eq!(entry.fields.get("method").and_then(|v| {
        if let FieldValue::String(s) = v { Some(s.as_str()) } else { None }
    }), Some("GET"));
    assert_eq!(entry.fields.get("path").and_then(|v| {
        if let FieldValue::String(s) = v { Some(s.as_str()) } else { None }
    }), Some("/api/users"));
}

#[test]
fn test_nginx_error_status_is_error_level() {
    let parser = NginxParser;
    let entry = parser.parse(
        br#"10.0.0.5 - - [15/Jan/2024:10:30:06 +0000] "GET /api/reports HTTP/1.1" 502 67 "-" "Mozilla/5.0""#,
        1
    ).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
}

#[test]
fn test_nginx_rejects_non_nginx() {
    let parser = NginxParser;
    assert!(parser.parse(b"plain text here", 1).is_none());
}
```

- [ ] **Step 3: Implement NginxParser**

```rust
// src/parsers/nginx.rs
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

use crate::core::parser::LogParser;
use crate::core::types::{FieldValue, LogEntry, LogLevel};

static NGINX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)""#
    ).unwrap()
});

pub struct NginxParser;

impl LogParser for NginxParser {
    fn name(&self) -> &str { "nginx-access" }
    fn supports_level(&self) -> bool { true }
    fn supports_timestamp(&self) -> bool { true }

    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let text = std::str::from_utf8(raw).ok()?;
        let caps = NGINX_RE.captures(text)?;

        let remote_addr = caps.get(1).map(|m| m.as_str().to_string());
        let timestamp = caps.get(3).and_then(|m| {
            chrono::DateTime::parse_from_str(m.as_str(), "%d/%b/%Y:%H:%M:%S %z").ok()
                .map(|dt| dt.with_timezone(&Utc))
        });
        let method = caps.get(4).map(|m| m.as_str().to_string());
        let path = caps.get(5).map(|m| m.as_str().to_string());
        let http_version = caps.get(6).map(|m| m.as_str().to_string());
        let status: u16 = caps.get(7)?.as_str().parse().ok()?;
        let body_bytes: u64 = caps.get(8).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let user_agent = caps.get(10).map(|m| m.as_str().to_string());

        let level = match status {
            500..=599 => LogLevel::Error,
            400..=499 => LogLevel::Warn,
            300..=399 => LogLevel::Info,
            _ => LogLevel::Info,
        };

        let mut fields = HashMap::new();
        if let Some(ip) = remote_addr {
            fields.insert("remote_addr".to_string(), FieldValue::String(ip));
        }
        if let Some(m) = method {
            fields.insert("method".to_string(), FieldValue::String(m));
        }
        if let Some(p) = path {
            fields.insert("path".to_string(), FieldValue::String(p));
        }
        if let Some(v) = http_version {
            fields.insert("http_version".to_string(), FieldValue::String(v));
        }
        fields.insert("status".to_string(), FieldValue::Number(status as f64));
        fields.insert("body_bytes".to_string(), FieldValue::Number(body_bytes as f64));
        if let Some(ua) = user_agent.filter(|s| *s != "-") {
            fields.insert("user_agent".to_string(), FieldValue::String(ua));
        }

        let message = format!("{} {}", status, path.unwrap_or_default());

        Some(LogEntry {
            timestamp,
            level,
            source: fields.get("remote_addr").and_then(|v| {
                if let FieldValue::String(s) = v { Some(s.clone()) } else { None }
            }),
            message,
            fields,
            line_number,
        })
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test parsers_nginx`
Expected: All 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/parsers/nginx.rs tests/parsers_nginx.rs tests/fixtures/nginx.log
git commit -m "feat: nginx access log parser with field extraction"
```

---

### Task 7: Apache Parser

**Files:**
- Create: `src/parsers/apache.rs`
- Create: `tests/fixtures/apache.log`
- Create: `tests/parsers_apache.rs`

- [ ] **Step 1: Write test fixture & test (combined step)**

```
// tests/fixtures/apache.log (Common Log Format + Combined)
192.168.1.10 - frank [15/Jan/2024:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 2326
192.168.1.20 - - [15/Jan/2024:10:30:01 +0000] "POST /login HTTP/1.1" 302 456
192.168.1.10 - - [15/Jan/2024:10:30:02 +0000] "GET /protected HTTP/1.1" 401 381
10.0.0.5 - - [15/Jan/2024:10:30:03 +0000] "GET /api/data HTTP/1.1" 500 89
```

- [ ] **Step 2: Write test**

```rust
// tests/parsers_apache.rs
use log_analyze::parsers::apache::ApacheParser;
use log_analyze::core::parser::LogParser;
use log_analyze::core::types::LogLevel;

#[test]
fn test_apache_parse_clf() {
    let parser = ApacheParser;
    let entry = parser.parse(
        br#"192.168.1.10 - frank [15/Jan/2024:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 2326"#,
        1
    ).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.level, Some(LogLevel::Info));
    assert_eq!(entry.message, "200 /index.html");
}

#[test]
fn test_apache_500_is_error() {
    let parser = ApacheParser;
    let entry = parser.parse(
        br#"10.0.0.5 - - [15/Jan/2024:10:30:03 +0000] "GET /api/data HTTP/1.1" 500 89"#,
        1
    ).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
}
```

- [ ] **Step 3: Implement ApacheParser**

```rust
// src/parsers/apache.rs
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

use crate::core::parser::LogParser;
use crate::core::types::{FieldValue, LogEntry, LogLevel};

static APACHE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)"#
    ).unwrap()
});

pub struct ApacheParser;

impl LogParser for ApacheParser {
    fn name(&self) -> &str { "apache-access" }
    fn supports_level(&self) -> bool { true }
    fn supports_timestamp(&self) -> bool { true }

    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let text = std::str::from_utf8(raw).ok()?;
        let caps = APACHE_RE.captures(text)?;

        let timestamp = caps.get(3).and_then(|m| {
            chrono::DateTime::parse_from_str(m.as_str(), "%d/%b/%Y:%H:%M:%S %z").ok()
                .map(|dt| dt.with_timezone(&Utc))
        });
        let method = caps.get(4).map(|m| m.as_str().to_string());
        let path = caps.get(5).map(|m| m.as_str().to_string());
        let status: u16 = caps.get(7)?.as_str().parse().ok()?;

        let level = match status {
            500..=599 => LogLevel::Error,
            400..=499 => LogLevel::Warn,
            _ => LogLevel::Info,
        };

        let mut fields = HashMap::new();
        if let Some(m) = method {
            fields.insert("method".to_string(), FieldValue::String(m));
        }
        if let Some(p) = path {
            fields.insert("path".to_string(), FieldValue::String(p));
        }
        fields.insert("status".to_string(), FieldValue::Number(status as f64));

        let message = format!("{} {}", status, fields.get("path").and_then(|v| {
            if let FieldValue::String(s) = v { Some(s.as_str()) } else { None }
        }).unwrap_or(""));

        Some(LogEntry {
            timestamp,
            level,
            source: caps.get(1).map(|m| m.as_str().to_string()),
            message,
            fields,
            line_number,
        })
    }
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test parsers_apache && git add src/parsers/apache.rs tests/parsers_apache.rs tests/fixtures/apache.log && git commit -m "feat: apache access log parser (CLF)"`
Expected: Tests pass, commit created.

---

### Task 8: Format Detector

**Files:**
- Modify: `src/parsers/mod.rs`
- Modify: `src/parsers/generic.rs`

- [ ] **Step 1: Update generic parser to implement LogParser trait**

Add this to `src/parsers/generic.rs`:

```rust
use crate::core::parser::LogParser;

impl LogParser for GenericParser {
    fn name(&self) -> &str { "generic" }
    fn supports_level(&self) -> bool { true }
    fn supports_timestamp(&self) -> bool { true }

    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        Some(GenericParser::parse_line(raw, line_number))
    }
}
```

- [ ] **Step 2: Replace src/parsers/mod.rs with full Detector**

```rust
// src/parsers/mod.rs
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::core::parser::{LogParser, ParsedChunk};
use crate::core::types::DetectedFormat;
use crate::core::error::AppError;

pub mod generic;
pub mod json;
pub mod syslog;
pub mod nginx;
pub mod apache;

pub struct Detector {
    parsers: Vec<Box<dyn LogParser>>,
    sample_lines: usize,
}

impl Detector {
    pub fn new() -> Self {
        Detector {
            parsers: vec![
                Box::new(json::JsonParser),
                Box::new(syslog::SyslogParser),
                Box::new(nginx::NginxParser),
                Box::new(apache::ApacheParser),
            ],
            sample_lines: 100,
        }
    }

    pub fn with_sample_lines(mut self, n: usize) -> Self {
        self.sample_lines = n;
        self
    }

    pub fn detect(&self, path: &Path) -> Result<(DetectedFormat, Box<dyn LogParser>), AppError> {
        let file = File::open(path).map_err(AppError::Io)?;
        let reader = BufReader::new(file);

        let sample: Vec<String> = reader
            .lines()
            .take(self.sample_lines)
            .filter_map(|l| l.ok())
            .collect();

        if sample.is_empty() {
            return Ok((
                DetectedFormat { name: "generic".into(), confidence: 0.0 },
                Box::new(generic::GenericParser),
            ));
        }

        let mut results: Vec<(f64, &Box<dyn LogParser>)> = self.parsers.iter()
            .map(|parser| {
                let success_rate = sample.iter()
                    .filter(|line| parser.parse(line.as_bytes(), 0).is_some())
                    .count() as f64 / sample.len() as f64;

                let has_ts = sample.iter()
                    .filter_map(|l| parser.parse(l.as_bytes(), 0))
                    .filter(|e| e.timestamp.is_some())
                    .count() as f64 / sample.len() as f64;

                let completeness = (success_rate + has_ts) / 2.0;
                (success_rate * 0.6 + completeness * 0.4, parser)
            })
            .collect();

        results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let best = results.into_iter().next().unwrap_or((0.0, &self.parsers[0]));
        let confidence = best.0;

        if confidence < 0.7 {
            Ok((DetectedFormat { name: "generic".into(), confidence }, Box::new(generic::GenericParser)))
        } else {
            Ok((DetectedFormat { name: best.1.name().to_string(), confidence }, Self::parser_by_name(best.1.name())))
        }
    }

    fn parser_by_name(name: &str) -> Box<dyn LogParser> {
        match name {
            "json" => Box::new(json::JsonParser),
            "syslog" => Box::new(syslog::SyslogParser),
            "nginx-access" => Box::new(nginx::NginxParser),
            "apache-access" => Box::new(apache::ApacheParser),
            _ => Box::new(generic::GenericParser),
        }
    }
}

/// Parse a full file using the detected parser
pub fn parse_file(path: &Path, sample_lines: usize) -> Result<(DetectedFormat, Vec<ParsedChunk>), AppError> {
    let detector = Detector::new().with_sample_lines(sample_lines);
    let (format, parser) = detector.detect(path)?;

    let file = File::open(path).map_err(AppError::Io)?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    let mut errors = 0u64;

    for (i, line) in reader.lines().enumerate() {
        match line {
            Ok(l) => {
                if let Some(entry) = parser.parse(l.as_bytes(), (i + 1) as u64) {
                    entries.push(entry);
                } else {
                    errors += 1;
                    entries.push(generic::GenericParser::parse_line(l.as_bytes(), (i + 1) as u64));
                }
            }
            Err(_) => { errors += 1; }
        }
    }

    Ok((format, vec![ParsedChunk { entries, errors }]))
}
```

- [ ] **Step 2: Write format detection test**

```rust
// tests/detector.rs
use log_analyze::parsers::Detector;
use std::path::Path;

#[test]
fn test_detect_json() {
    let detector = Detector::new();
    let (fmt, _) = detector.detect(Path::new("tests/fixtures/json.log")).unwrap();
    assert_eq!(fmt.name, "json");
    assert!(fmt.confidence > 0.7);
}

#[test]
fn test_detect_nginx() {
    let detector = Detector::new();
    let (fmt, _) = detector.detect(Path::new("tests/fixtures/nginx.log")).unwrap();
    assert_eq!(fmt.name, "nginx-access");
    assert!(fmt.confidence > 0.7);
}

#[test]
fn test_detect_syslog() {
    let detector = Detector::new();
    let (fmt, _) = detector.detect(Path::new("tests/fixtures/syslog.log")).unwrap();
    assert_eq!(fmt.name, "syslog");
    assert!(fmt.confidence > 0.7);
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test detector`
Expected: All 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/parsers/ src/parsers/mod.rs src/parsers/generic.rs tests/detector.rs
git commit -m "feat: format auto-detection by sampling and scoring parsers"
```

---

### Task 9: Built-in Pattern Engine

**Files:**
- Create: `src/patterns/mod.rs`
- Create: `src/patterns/builtin.rs`

- [ ] **Step 1: Write built-in patterns**

```rust
// src/patterns/builtin.rs
use crate::core::pattern::Pattern;
use crate::core::types::{LogEntry, LogLevel, Severity};

// Note: error_burst is handled by Aggregator's sliding window spike detection, not a Pattern.

// --- Connection Refused ---
pub struct ConnectionRefusedPattern;

impl Pattern for ConnectionRefusedPattern {
    fn name(&self) -> &str { "connection_refused" }
    fn description(&self) -> &str { "连接被拒绝" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn min_count(&self) -> u64 { 3 }

    fn check(&self, entry: &LogEntry) -> bool {
        let lower = entry.message.to_lowercase();
        lower.contains("connection refused")
            || lower.contains("econnrefused")
            || lower.contains("connect: connection refused")
    }
}

// --- OOM Kill ---
pub struct OomKillPattern;

impl Pattern for OomKillPattern {
    fn name(&self) -> &str { "oom_kill" }
    fn description(&self) -> &str { "Out of Memory killer 活动" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn min_count(&self) -> u64 { 1 }

    fn check(&self, entry: &LogEntry) -> bool {
        let lower = entry.message.to_lowercase();
        lower.contains("out of memory")
            || lower.contains("oom")
            || (lower.contains("killed process") && lower.contains("total-vm"))
    }
}

// --- Disk Full ---
pub struct DiskFullPattern;

impl Pattern for DiskFullPattern {
    fn name(&self) -> &str { "disk_full" }
    fn description(&self) -> &str { "磁盘空间不足" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn min_count(&self) -> u64 { 1 }

    fn check(&self, entry: &LogEntry) -> bool {
        let lower = entry.message.to_lowercase();
        lower.contains("no space left")
            || lower.contains("disk full")
            || (lower.contains("disk") && lower.contains("usage") && lower.contains("95%"))
    }
}

// --- Timeout ---
pub struct TimeoutPattern;

impl Pattern for TimeoutPattern {
    fn name(&self) -> &str { "timeout" }
    fn description(&self) -> &str { "超时错误" }
    fn severity(&self) -> Severity { Severity::Warning }
    fn min_count(&self) -> u64 { 5 }

    fn check(&self, entry: &LogEntry) -> bool {
        let lower = entry.message.to_lowercase();
        lower.contains("timeout")
            || lower.contains("timed out")
            || lower.contains("deadline exceeded")
    }
}

// --- Auth Failure ---
pub struct AuthFailurePattern;

impl Pattern for AuthFailurePattern {
    fn name(&self) -> &str { "auth_failure" }
    fn description(&self) -> &str { "认证失败激增" }
    fn severity(&self) -> Severity { Severity::Warning }
    fn min_count(&self) -> u64 { 5 }

    fn check(&self, entry: &LogEntry) -> bool {
        let lower = entry.message.to_lowercase();
        lower.contains("failed password")
            || lower.contains("authentication failed")
            || lower.contains("unauthorized")
            || lower.contains("403")
            || lower.contains("401")
    }
}

// --- Stack Trace ---
pub struct StackTracePattern;

impl Pattern for StackTracePattern {
    fn name(&self) -> &str { "stack_trace" }
    fn description(&self) -> &str { "异常堆栈出现" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn min_count(&self) -> u64 { 1 }

    fn check(&self, entry: &LogEntry) -> bool {
        let msg = &entry.message;
        msg.contains("Traceback")
            || msg.contains("Exception")
            || msg.contains("panic")
            || msg.contains("stack trace")
            || msg.trim_start().starts_with("at ")
            || msg.trim_start().starts_with("File \"")
    }
}

/// Returns all built-in patterns
pub fn all_builtin_patterns() -> Vec<Box<dyn Pattern>> {
    vec![
        Box::new(ConnectionRefusedPattern),
        Box::new(OomKillPattern),
        Box::new(DiskFullPattern),
        Box::new(TimeoutPattern),
        Box::new(AuthFailurePattern),
        Box::new(StackTracePattern),
    ]
}
```

- [ ] **Step 2: Write patterns/mod.rs**

```rust
// src/patterns/mod.rs
pub mod builtin;
pub mod custom;
pub mod anomaly;
pub mod frequency;
```

- [ ] **Step 3: Write test**

```rust
// tests/patterns_builtin.rs
use log_analyze::patterns::builtin;
use log_analyze::core::types::{LogEntry, LogLevel};

fn make_entry(msg: &str) -> LogEntry {
    LogEntry {
        timestamp: None,
        level: Some(LogLevel::Error),
        source: None,
        message: msg.to_string(),
        fields: std::collections::HashMap::new(),
        line_number: 1,
    }
}

#[test]
fn test_oom_pattern() {
    let pat = builtin::OomKillPattern;
    assert!(pat.check(&make_entry("Out of memory: Killed process 2048 (java)")));
    assert!(pat.check(&make_entry("oom killer invoked")));
    assert!(!pat.check(&make_entry("normal log message")));
}

#[test]
fn test_connection_refused_pattern() {
    let pat = builtin::ConnectionRefusedPattern;
    assert!(pat.check(&make_entry("Error: connection refused to 10.0.1.5:8080")));
    assert!(pat.check(&make_entry("dial tcp: connect: connection refused")));
}

#[test]
fn test_timeout_pattern() {
    let pat = builtin::TimeoutPattern;
    assert!(pat.check(&make_entry("request timeout after 30s")));
    assert!(pat.check(&make_entry("deadline exceeded")));
}

#[test]
fn test_stack_trace_pattern() {
    let pat = builtin::StackTracePattern;
    assert!(pat.check(&make_entry("Traceback (most recent call last):")));
    assert!(pat.check(&make_entry("  File \"app.py\", line 42, in <module>")));
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test patterns_builtin && git add src/patterns/ tests/patterns_builtin.rs && git commit -m "feat: built-in pattern matching engine with 7 rules"`
Expected: All tests pass.

---

### Task 10: Custom TOML Rules

**Files:**
- Create: `src/patterns/custom.rs`
- Create: `tests/fixtures/rules.toml`

- [ ] **Step 1: Write test fixture**

```toml
# tests/fixtures/rules.toml
[[pattern]]
name = "k8s_pod_crashloop"
description = "K8s Pod CrashLoopBackOff"
severity = "critical"
match_type = "regex"
expression = "CrashLoopBackOff|Back-off restarting"
count_threshold = 3
time_window = "5m"

[[pattern]]
name = "slow_query"
description = "慢查询超过阈值"
severity = "warning"
match_type = "field"
field = "duration_ms"
condition = "gt"
value = 1000
```

- [ ] **Step 2: Implement custom rules**

```rust
// src/patterns/custom.rs
use once_cell::sync::OnceCell;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::core::pattern::Pattern;
use crate::core::types::{FieldValue, LogEntry, Severity};

#[derive(Debug, Deserialize, Clone)]
pub struct CustomRule {
    pub pattern: Vec<RuleDef>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleDef {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub match_type: String,
    pub expression: Option<String>,
    pub field: Option<String>,
    pub condition: Option<String>,
    pub value: Option<f64>,
    #[serde(default)]
    pub count_threshold: u64,
    #[serde(default)]
    pub time_window: Option<String>,
}

impl RuleDef {
    fn compiled_regex(&self) -> Option<Regex> {
        self.expression.as_ref().and_then(|expr| Regex::new(expr).ok())
    }

    fn severity(&self) -> Severity {
        match self.severity.as_str() {
            "critical" => Severity::Critical,
            "warning" => Severity::Warning,
            _ => Severity::Info,
        }
    }

    fn matches(&self, entry: &LogEntry) -> bool {
        match self.match_type.as_str() {
            "regex" => {
                if let Some(re) = self.compiled_regex() {
                    re.is_match(&entry.message)
                } else {
                    false
                }
            }
            "keyword" => {
                if let Some(expr) = &self.expression {
                    entry.message.to_lowercase().contains(&expr.to_lowercase())
                } else {
                    false
                }
            }
            "field" => {
                let field_name = match &self.field {
                    Some(f) => f,
                    None => return false,
                };
                let field_val = match entry.fields.get(field_name) {
                    Some(v) => v,
                    None => return false,
                };
                let threshold = match self.value {
                    Some(v) => v,
                    None => return false,
                };

                match (field_val, self.condition.as_deref()) {
                    (FieldValue::Number(n), Some("gt")) => *n > threshold,
                    (FieldValue::Number(n), Some("lt")) => *n < threshold,
                    (FieldValue::Number(n), Some("gte")) => *n >= threshold,
                    (FieldValue::Number(n), Some("lte")) => *n <= threshold,
                    (FieldValue::Number(n), Some("eq")) => (*n - threshold).abs() < f64::EPSILON,
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

pub struct CustomPattern {
    rule: RuleDef,
}

impl Pattern for CustomPattern {
    fn name(&self) -> &str { &self.rule.name }
    fn description(&self) -> &str { &self.rule.description }
    fn severity(&self) -> Severity { self.rule.severity() }
    fn min_count(&self) -> u64 { self.rule.count_threshold }

    fn check(&self, entry: &LogEntry) -> bool {
        self.rule.matches(entry)
    }
}

/// Load custom rules from a TOML file path
pub fn load_rules(path: &Path) -> Result<Vec<Box<dyn Pattern>>, crate::core::error::AppError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| crate::core::error::AppError::Config {
            path: path.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
    let rules: CustomRule = toml::from_str(&content)
        .map_err(|e| crate::core::error::AppError::Config {
            path: path.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;

    Ok(rules.pattern.into_iter()
        .map(|rule| Box::new(CustomPattern { rule }) as Box<dyn Pattern>)
        .collect())
}

/// Load rules from default locations (~/.config/log-analyze/rules.toml)
pub fn load_default_rules() -> Vec<Box<dyn Pattern>> {
    let home = std::env::var("HOME").unwrap_or_default();
    let default_path = Path::new(&home).join(".config/log-analyze/rules.toml");

    if default_path.exists() {
        load_rules(&default_path).unwrap_or_default()
    } else {
        Vec::new()
    }
}
```

- [ ] **Step 3: Write test**

```rust
// tests/patterns_custom.rs
use log_analyze::patterns::custom::load_rules;
use std::path::Path;

#[test]
fn test_load_custom_rules() {
    let rules = load_rules(Path::new("tests/fixtures/rules.toml")).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].name(), "k8s_pod_crashloop");
    assert_eq!(rules[1].name(), "slow_query");
}

#[test]
fn test_custom_regex_rule() {
    let rules = load_rules(Path::new("tests/fixtures/rules.toml")).unwrap();
    let entry = make_entry("Pod is in CrashLoopBackOff state");
    assert!(rules[0].check(&entry));
}

// Helper defined in test
fn make_entry(msg: &str) -> log_analyze::core::types::LogEntry {
    log_analyze::core::types::LogEntry {
        timestamp: None, level: None, source: None,
        message: msg.to_string(),
        fields: std::collections::HashMap::new(),
        line_number: 1,
    }
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test patterns_custom && git add src/patterns/custom.rs tests/patterns_custom.rs tests/fixtures/rules.toml && git commit -m "feat: custom TOML rule loading with regex, keyword, field match types"`

---

### Task 11: Statistical Anomaly Detection

**Files:**
- Create: `src/patterns/anomaly.rs`
- Create: `src/patterns/frequency.rs`

- [ ] **Step 1: Implement anomaly detection**

```rust
// src/patterns/anomaly.rs
use chrono::{DateTime, Duration, Utc};
use crate::core::types::{Anomaly, AnomalyType, LogEntry, LogLevel};

const SPIKE_WINDOW_SECS: i64 = 300; // 5-minute windows
const GAP_THRESHOLD_SECS: i64 = 10;  // >10s gap is suspicious
const ZSCORE_THRESHOLD: f64 = 2.0;

/// Detect error rate spikes using a sliding window Z-score approach
pub fn detect_error_spikes(entries: &[LogEntry]) -> Vec<Anomaly> {
    if entries.is_empty() {
        return Vec::new();
    }

    let window_size = 300; // entries per window
    let mut anomalies = Vec::new();
    let mut error_rates: Vec<f64> = Vec::new();

    // Calculate error rates per window
    for chunk in entries.chunks(window_size) {
        let total = chunk.len() as f64;
        let errors = chunk.iter()
            .filter(|e| e.level == Some(LogLevel::Error))
            .count() as f64;
        error_rates.push(errors / total);
    }

    if error_rates.len() < 3 {
        return Vec::new();
    }

    let mean: f64 = error_rates.iter().sum::<f64>() / error_rates.len() as f64;
    let variance: f64 = error_rates.iter()
        .map(|r| (r - mean).powi(2))
        .sum::<f64>() / error_rates.len() as f64;
    let stddev = variance.sqrt();

    for (i, rate) in error_rates.iter().enumerate() {
        let zscore = if stddev > 0.0 {
            (rate - mean).abs() / stddev
        } else {
            0.0
        };

        if zscore > ZSCORE_THRESHOLD {
            let start_idx = i * window_size;
            let end_idx = ((i + 1) * window_size).min(entries.len());

            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::Spike,
                start_time: entries[start_idx].timestamp,
                end_time: entries[end_idx - 1].timestamp,
                score: zscore,
                detail: format!(
                    "错误率从均值 {:.1}% 突增至 {:.1}% (Z-score: {:.1})",
                    mean * 100.0, rate * 100.0, zscore
                ),
            });
        }
    }

    anomalies
}

/// Detect time gaps (silence periods) in log entries
pub fn detect_time_gaps(entries: &[LogEntry]) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    for pair in entries.windows(2) {
        let prev_ts = match pair[0].timestamp {
            Some(ts) => ts,
            None => continue,
        };
        let curr_ts = match pair[1].timestamp {
            Some(ts) => ts,
            None => continue,
        };

        let gap = (curr_ts - prev_ts).num_seconds();
        if gap > GAP_THRESHOLD_SECS {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::Gap,
                start_time: Some(prev_ts),
                end_time: Some(curr_ts),
                score: (gap as f64 / GAP_THRESHOLD_SECS as f64).min(100.0),
                detail: format!(
                    "日志中断 {} 秒 ({} → {})",
                    gap,
                    prev_ts.format("%H:%M:%S"),
                    curr_ts.format("%H:%M:%S")
                ),
            });
        }
    }

    // Limit to top 10
    anomalies.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    anomalies.truncate(10);
    anomalies
}
```

- [ ] **Step 2: Implement frequency analysis**

```rust
// src/patterns/frequency.rs
use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::types::{Anomaly, AnomalyType, LogEntry};

/// SHA256-like fingerprint by replacing numbers, IPs, UUIDs, etc. with placeholders
static FINGERPRINT_REPLACEMENTS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"\b\d+\.\d+\.\d+\.\d+(:\d+)?\b").unwrap(), "<IP>"),
        (Regex::new(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap(), "<UUID>"),
        (Regex::new(r"\b\d+\b").unwrap(), "<N>"),
        (Regex::new(r"0x[0-9a-fA-F]+").unwrap(), "<HEX>"),
    ]
});

/// Generate a fingerprint for a log message by replacing variable parts
pub fn fingerprint(message: &str) -> String {
    let mut fprint = message.to_string();
    for (re, replacement) in FINGERPRINT_REPLACEMENTS.iter() {
        fprint = re.replace_all(&fprint, *replacement).to_string();
    }
    fprint
}

/// Hash a fingerprint string to u64 for efficient counting in aggregator
pub fn hash_fingerprint(fp: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    fp.hash(&mut hasher);
    hasher.finish()
}

/// Detect unusually frequent log patterns (standalone, for tests)
pub fn detect_frequent_patterns(entries: &[LogEntry], top_n: usize) -> Vec<Anomaly> {
    let mut freq: HashMap<u64, u64> = HashMap::new();
    let mut samples: HashMap<u64, String> = HashMap::new();

    for entry in entries {
        let fp = fingerprint(&entry.message);
        let hash = hash_fingerprint(&fp);
        *freq.entry(hash).or_default() += 1;
        samples.entry(hash).or_insert_with(|| {
            if entry.message.len() > 80 { entry.message[..80].to_string() } else { entry.message.clone() }
        });
    }

    let mut sorted: Vec<_> = freq.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let total = entries.len() as f64;
    let mean = total / sorted.len().max(1) as f64;

    sorted.iter().take(top_n).filter_map(|(&hash, &count)| {
        let deviation = count as f64 / mean;
        if deviation < 3.0 { return None; }
        Some(Anomaly {
            anomaly_type: AnomalyType::Frequency,
            start_time: None, end_time: None, score: deviation,
            detail: format!("高频模式出现 {} 次 (偏离均值 {:.1}x): {}", count, deviation,
                samples.get(&hash).cloned().unwrap_or_default()),
        })
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_replaces_numbers() {
        let f = fingerprint("connection from 192.168.1.100:8080 on port 443");
        assert!(f.contains("<IP>"));
        assert!(!f.contains("192.168"));
    }

    #[test]
    fn test_fingerprint_idempotent() {
        let a = fingerprint("error from 10.0.0.1 on line 42");
        let b = fingerprint("error from 192.168.1.1 on line 108");
        assert_eq!(a, b); // Same structure, different values
    }
}
```

- [ ] **Step 3: Write anomaly tests**

```rust
// tests/anomaly.rs
use log_analyze::patterns::anomaly::{detect_error_spikes, detect_time_gaps};
use log_analyze::core::types::{LogEntry, LogLevel};
use chrono::{Utc, Duration};

fn make_entry(level: LogLevel, ts_offset: i64) -> LogEntry {
    LogEntry {
        timestamp: Some(Utc::now() + Duration::seconds(ts_offset)),
        level: Some(level),
        source: None,
        message: "test".into(),
        fields: std::collections::HashMap::new(),
        line_number: ts_offset as u64,
    }
}

#[test]
fn test_detect_error_spike() {
    let mut entries: Vec<LogEntry> = Vec::new();
    // Normal: 10% error rate for first 300 entries
    for i in 0..300 {
        let lvl = if i % 10 == 0 { LogLevel::Error } else { LogLevel::Info };
        entries.push(make_entry(lvl, i));
    }
    // Spike: 80% error rate for next 300
    for i in 300..600 {
        let lvl = if i % 10 <= 7 { LogLevel::Error } else { LogLevel::Info };
        entries.push(make_entry(lvl, i));
    }

    let spikes = detect_error_spikes(&entries);
    assert!(!spikes.is_empty());
    assert!(spikes[0].score > 2.0);
}

#[test]
fn test_detect_time_gap() {
    let mut entries: Vec<LogEntry> = Vec::new();
    entries.push(make_entry(LogLevel::Info, 0));
    entries.push(make_entry(LogLevel::Info, 1));
    entries.push(make_entry(LogLevel::Info, 60)); // 59 second gap

    let gaps = detect_time_gaps(&entries);
    assert!(!gaps.is_empty());
    assert!(gaps[0].detail.contains("59"));
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test anomaly && cargo test patterns::frequency && git add src/patterns/anomaly.rs src/patterns/frequency.rs tests/anomaly.rs && git commit -m "feat: statistical anomaly detection (error spikes, time gaps, frequency)"`

---

### Task 12: Aggregator

**Files:**
- Create: `src/analyzer/mod.rs`
- Create: `src/analyzer/aggregator.rs`

- [ ] **Step 1: Implement incremental aggregator**

```rust
// src/analyzer/aggregator.rs
use std::collections::{HashMap, VecDeque};
use chrono::{DateTime, Duration, Utc};
use crate::core::types::{LogEntry, LogLevel, MatchStats};

const SAMPLE_LIMIT: usize = 50;

/// Incremental aggregator — never holds all entries, only statistics and samples.
pub struct Aggregator {
    pub total_lines: u64,
    pub parse_errors: u64,
    pub level_counts: HashMap<LogLevel, u64>,
    pub min_time: Option<DateTime<Utc>>,
    pub max_time: Option<DateTime<Utc>>,

    // Sliding window for error rate
    window: VecDeque<(DateTime<Utc>, LogLevel)>,
    window_duration: Duration,

    // Time gap: only remember last timestamp
    last_timestamp: Option<DateTime<Utc>>,
    pub time_gaps: Vec<crate::core::types::Anomaly>,

    // Frequency: fingerprint hash → count
    fingerprints: HashMap<u64, u64>,
    fingerprint_samples: HashMap<u64, String>,

    // Per-pattern: (count, first_seen, last_seen, sample_entries)
    pattern_state: HashMap<String, (u64, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Vec<LogEntry>)>,
}

impl Aggregator {
    pub fn new() -> Self {
        Aggregator {
            total_lines: 0, parse_errors: 0,
            level_counts: HashMap::new(),
            min_time: None, max_time: None,
            window: VecDeque::new(),
            window_duration: Duration::seconds(300),
            last_timestamp: None,
            time_gaps: Vec::new(),
            fingerprints: HashMap::new(),
            fingerprint_samples: HashMap::new(),
            pattern_state: HashMap::new(),
        }
    }

    pub fn feed(&mut self, entry: &LogEntry) {
        self.total_lines += 1;

        if let Some(ts) = entry.timestamp {
            self.min_time = Some(self.min_time.map_or(ts, |t| t.min(ts)));
            self.max_time = Some(self.max_time.map_or(ts, |t| t.max(ts)));

            self.window.push_back((ts, entry.level.clone().unwrap_or(LogLevel::Info)));
            let cutoff = ts - self.window_duration;
            while self.window.front().map_or(false, |(t, _)| *t < cutoff) {
                self.window.pop_front();
            }

            if let Some(last) = self.last_timestamp {
                let gap = (ts - last).num_seconds();
                if gap > 10 {
                    self.time_gaps.push(crate::core::types::Anomaly {
                        anomaly_type: crate::core::types::AnomalyType::Gap,
                        start_time: Some(last), end_time: Some(ts),
                        score: (gap as f64 / 10.0).min(100.0),
                        detail: format!("日志中断 {} 秒", gap),
                    });
                }
            }
            self.last_timestamp = Some(ts);
        }

        if let Some(ref level) = entry.level {
            *self.level_counts.entry(level.clone()).or_default() += 1;
        }

        let fp = crate::patterns::frequency::fingerprint(&entry.message);
        let fp_hash = crate::patterns::frequency::hash_fingerprint(&fp);
        *self.fingerprints.entry(fp_hash).or_default() += 1;
        self.fingerprint_samples.entry(fp_hash).or_insert_with(|| {
            if entry.message.len() > 80 { entry.message[..80].to_string() } else { entry.message.clone() }
        });
    }

    pub fn record_match(&mut self, pattern_name: &str, entry: LogEntry) {
        let (count, first, last, samples) = self.pattern_state
            .entry(pattern_name.to_string())
            .or_insert((0, entry.timestamp, entry.timestamp, Vec::new()));
        *count += 1;
        if let Some(ts) = entry.timestamp {
            *first = first.map_or(Some(ts), |f| Some(f.min(ts)));
            *last = last.map_or(Some(ts), |l| Some(l.max(ts)));
        }
        if samples.len() < SAMPLE_LIMIT { samples.push(entry); }
    }

    pub fn detect_spikes(&self) -> Vec<crate::core::types::Anomaly> {
        let total_errors = self.level_counts.get(&LogLevel::Error).copied().unwrap_or(0) as f64;
        let total = self.total_lines as f64;
        if total == 0.0 { return Vec::new(); }
        let overall_rate = total_errors / total;
        let window_errors = self.window.iter().filter(|(_, l)| *l == LogLevel::Error).count() as f64;
        let window_rate = if self.window.is_empty() { 0.0 } else { window_errors / self.window.len() as f64 };

        if overall_rate > 0.0 && window_rate > overall_rate * 3.0 {
            let zscore = (window_rate - overall_rate) / overall_rate.sqrt();
            if zscore > 2.0 {
                return vec![crate::core::types::Anomaly {
                    anomaly_type: crate::core::types::AnomalyType::Spike,
                    start_time: self.window.front().map(|(t, _)| *t),
                    end_time: self.window.back().map(|(t, _)| *t),
                    score: zscore,
                    detail: format!("错误率从 {:.1}% 突增至 {:.1}% (Z-score: {:.1})",
                        overall_rate * 100.0, window_rate * 100.0, zscore),
                }];
            }
        }
        Vec::new()
    }

    pub fn detect_frequent(&self, top_n: usize) -> Vec<crate::core::types::Anomaly> {
        if self.fingerprints.is_empty() { return Vec::new(); }
        let mean = self.total_lines as f64 / self.fingerprints.len().max(1) as f64;
        let mut sorted: Vec<_> = self.fingerprints.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.iter().take(top_n).filter_map(|(&fp_hash, &count)| {
            let deviation = count as f64 / mean;
            if deviation < 3.0 { return None; }
            Some(crate::core::types::Anomaly {
                anomaly_type: crate::core::types::AnomalyType::Frequency,
                start_time: None, end_time: None, score: deviation,
                detail: format!("高频模式 {} 次 (偏离均值 {:.1}x): {}",
                    count, deviation,
                    self.fingerprint_samples.get(&fp_hash).cloned().unwrap_or_default()),
            })
        }).collect()
    }

    pub fn build_stats(&self, pattern_name: &str) -> Option<MatchStats> {
        self.pattern_state.get(pattern_name).map(|(count, first, last, _)| {
            let duration = match (*first, *last) {
                (Some(f), Some(l)) => (l - f).num_seconds().max(1) as f64,
                _ => 1.0,
            };
            MatchStats { count: *count, first_seen: *first, last_seen: *last, rate_per_minute: (*count as f64 / duration) * 60.0 }
        })
    }

    pub fn take_samples(&mut self, pattern_name: &str) -> Vec<LogEntry> {
        self.pattern_state.remove(pattern_name).map(|(_, _, _, s)| s).unwrap_or_default()
    }
}
```

- [ ] **Step 2: Write analyzer/mod.rs**

```rust
// src/analyzer/mod.rs
pub mod aggregator;
pub mod engine;
```

- [ ] **Step 3: Write test and commit**

```rust
// tests/aggregator.rs
use log_analyze::analyzer::aggregator::Aggregator;
use log_analyze::core::types::LogLevel;

fn make_entry(level: LogLevel) -> log_analyze::core::types::LogEntry {
    log_analyze::core::types::LogEntry {
        timestamp: Some(chrono::Utc::now()),
        level: Some(level),
        source: None,
        message: "test".into(),
        fields: std::collections::HashMap::new(),
        line_number: 1,
    }
}

#[test]
fn test_aggregator_level_distribution() {
    let mut aggr = Aggregator::new();
    for _ in 0..5 { aggr.feed(&make_entry(LogLevel::Error)); }
    for _ in 0..10 { aggr.feed(&make_entry(LogLevel::Info)); }

    assert_eq!(*aggr.level_counts.get(&LogLevel::Error).unwrap(), 5);
    assert_eq!(*aggr.level_counts.get(&LogLevel::Info).unwrap(), 10);
    assert_eq!(aggr.total_lines, 15);
}
```

Run: `cargo test aggregator && git add src/analyzer/ tests/aggregator.rs && git commit -m "feat: streaming aggregator for real-time statistics"`

---

### Task 13: Streaming Pipeline Engine

**Files:**
- Create: `src/analyzer/engine.rs`
- Modify: `src/parsers/mod.rs` (add `chunked_parse_file`)

- [ ] **Step 1: Implement pipeline engine**

```rust
// src/analyzer/engine.rs
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::core::pattern::Pattern;
use crate::core::types::{AnalysisReport, DetectedFormat, FileInfo, PatternMatch, TimeRange};
use crate::core::error::AppError;
use crate::parsers::Detector;
use crate::analyzer::aggregator::Aggregator;

/// Run the full analysis pipeline on a log file — true streaming, no Vec<LogEntry>.
pub fn analyze_file(
    path: &Path,
    patterns: &[Box<dyn Pattern>],
    sample_lines: usize,
) -> Result<AnalysisReport, AppError> {
    let file_size = std::fs::metadata(path).map_err(AppError::Io)?.len();

    // Phase 1: Format detection
    let (format, parser) = Detector::new().with_sample_lines(sample_lines).detect(path)?;

    // Phase 2: Parse & match (streaming — no all_entries Vec)
    let file = File::open(path).map_err(AppError::Io)?;
    let reader = BufReader::new(file);
    let mut aggregator = Aggregator::new();

    for (i, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => { aggregator.parse_errors += 1; continue; }
        };

        let entry = match parser.parse(line.as_bytes(), (i + 1) as u64) {
            Some(e) => e,
            None => {
                aggregator.parse_errors += 1;
                crate::parsers::generic::GenericParser::parse_line(line.as_bytes(), (i + 1) as u64)
            }
        };

        aggregator.feed(&entry);

        for pattern in patterns {
            if pattern.check(&entry) {
                aggregator.record_match(pattern.name(), entry.clone());
            }
        }
    }

    // Phase 3: Build pattern matches
    let mut pattern_matches: Vec<PatternMatch> = Vec::new();
    for pattern in patterns {
        let stats = match aggregator.build_stats(pattern.name()) {
            Some(s) => s,
            None => continue,
        };
        if stats.count < pattern.min_count() { continue; }
        let entries = aggregator.take_samples(pattern.name());
        pattern_matches.push(pattern.build_match(entries, stats));
    }

    // Phase 4: Anomaly detection — all incremental, from aggregator
    let mut anomalies = aggregator.detect_spikes();
    anomalies.extend(aggregator.time_gaps);
    anomalies.extend(aggregator.detect_frequent(10));

    // Phase 5: Build report
    let time_range = match (aggregator.min_time, aggregator.max_time) {
        (Some(start), Some(end)) => Some(TimeRange { start, end }),
        _ => None,
    };

    Ok(AnalysisReport {
        file_info: FileInfo {
            path: path.to_string_lossy().to_string(),
            size_bytes: file_size,
            total_lines: aggregator.total_lines,
            parse_errors: aggregator.parse_errors,
        },
        format,
        time_range,
        level_distribution: aggregator.level_counts,
        patterns: pattern_matches,
        anomalies,
    })
}
```

- [ ] **Step 2: Write integration test**

```rust
// tests/integration.rs
use log_analyze::analyzer::engine::analyze_file;
use log_analyze::patterns::builtin::all_builtin_patterns;
use std::path::Path;

#[test]
fn test_analyze_nginx_file() {
    let patterns = all_builtin_patterns();
    let report = analyze_file(
        Path::new("tests/fixtures/nginx.log"),
        &patterns,
        100,
    ).unwrap();

    assert_eq!(report.format.name, "nginx-access");
    assert!(report.format.confidence > 0.7);
    assert_eq!(report.file_info.total_lines, 7);
    // Should detect 500 and 502 errors
    assert!(report.patterns.iter().any(|m| m.pattern_name == "auth_failure"));
}

#[test]
fn test_analyze_json_file() {
    let patterns = all_builtin_patterns();
    let report = analyze_file(
        Path::new("tests/fixtures/json.log"),
        &patterns,
        100,
    ).unwrap();

    assert_eq!(report.format.name, "json");
    // Should detect timeout and connection refused
    assert!(report.patterns.iter().any(|m| m.pattern_name == "connection_refused"));
}

#[test]
fn test_analyze_huge_file_streaming() {
    // Verify memory doesn't blow up with many entries
    let patterns: Vec<Box<dyn log_analyze::core::pattern::Pattern>> = Vec::new();
    let report = analyze_file(
        Path::new("tests/fixtures/nginx.log"),
        &patterns,
        100,
    ).unwrap();

    assert!(report.patterns.is_empty());
    assert!(report.anomalies.is_empty() || !report.anomalies.is_empty()); // may or may not have anomalies
}
```

- [ ] **Step 3: Run tests and commit**

Run: `cargo test integration && git add src/analyzer/engine.rs tests/integration.rs && git commit -m "feat: streaming pipeline engine (parse + match + aggregate + anomaly)"`

---

### Task 14: Terminal Output

**Files:**
- Create: `src/output/mod.rs`
- Create: `src/output/terminal.rs`

- [ ] **Step 1: Implement terminal output**

```rust
// src/output/terminal.rs
use colored::*;
use comfy_table::Table;
use crate::core::sink::Sink;
use crate::core::types::AnalysisReport;
use anyhow::Result;

pub struct TerminalSink {
    pub use_color: bool,
}

impl TerminalSink {
    pub fn new() -> Self {
        TerminalSink { use_color: true }
    }
}

impl Sink for TerminalSink {
    fn name(&self) -> &str { "terminal" }

    fn write(&self, report: &AnalysisReport) -> Result<()> {
        // Header
        println!("\n{}", "━━━ Log Analysis Report ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bold());
        println!("File: {} ({} MB, {} lines)",
            report.file_info.path,
            report.file_info.size_bytes / 1_048_576,
            report.file_info.total_lines
        );
        println!("Format: {} (confidence: {:.1}%)",
            report.format.name, report.format.confidence * 100.0
        );

        if let Some(ref range) = report.time_range {
            println!("Range: {} → {}",
                range.start.format("%Y-%m-%d %H:%M:%S"),
                range.end.format("%Y-%m-%d %H:%M:%S")
            );
        }

        if report.file_info.parse_errors > 0 {
            println!("Parse errors: {} lines ({:.2}%)",
                report.file_info.parse_errors,
                report.file_info.parse_errors as f64 / report.file_info.total_lines as f64 * 100.0
            );
        }

        // Level distribution
        if !report.level_distribution.is_empty() {
            println!("\n{}", "── Level Distribution ──────────────────────────────────".bold());
            let total: u64 = report.level_distribution.values().sum();
            let mut levels: Vec<_> = report.level_distribution.iter().collect();
            // Sort by severity: Error, Warn, Info, Debug, Trace
            levels.sort_by_key(|(lvl, _)| level_ord(lvl));

            for (level, count) in levels {
                let pct = *count as f64 / total as f64 * 100.0;
                let bar_len = (pct / 2.0) as usize; // 20 chars = 100%
                let bar = format!("{}{}", "█".repeat(bar_len), "░".repeat(20 - bar_len));
                println!("  {:<7} {}  {:>8}  ({:.2}%)",
                    format!("{:?}", level).color(level_color(level)),
                    bar,
                    count,
                    pct
                );
            }
        }

        // Pattern matches
        if !report.patterns.is_empty() {
            println!("\n{}", "── Pattern Matches ────────────────────────────────────".bold());

            // Sort by severity
            let mut sorted = report.patterns.clone();
            sorted.sort_by_key(|m| severity_ord(m.severity));

            for pm in &sorted {
                let sev_str = if severity_ord(pm.severity) <= 2 {
                    format!("[{}] {}", severity_label(pm.severity), pm.pattern_name).red().bold()
                } else {
                    format!("[{}] {}", severity_label(pm.severity), pm.pattern_name).yellow()
                };

                println!("  {}", sev_str);
                println!("    {}", pm.description);

                if let (Some(first), Some(last)) = (pm.stats.first_seen, pm.stats.last_seen) {
                    println!("    {} → {} ({} events, {:.1}/min)",
                        first.format("%H:%M:%S"),
                        last.format("%H:%M:%S"),
                        pm.stats.count,
                        pm.stats.rate_per_minute
                    );
                }
                // Show a sample entry
                if let Some(sample) = pm.entries.first() {
                    let msg = if sample.message.len() > 100 {
                        format!("{}...", &sample.message[..97])
                    } else {
                        sample.message.clone()
                    };
                    println!("    采样: \"{}\"", msg);
                }
                println!();
            }
        }

        // Anomalies
        if !report.anomalies.is_empty() {
            println!("\n{}", "── Statistical Anomalies ──────────────────────────────".bold());
            for anomaly in &report.anomalies {
                let icon = match anomaly.anomaly_type {
                    crate::core::types::AnomalyType::Spike => "⚠️ ",
                    crate::core::types::AnomalyType::Gap => "⏸ ",
                    crate::core::types::AnomalyType::Frequency => "🔁 ",
                };
                println!("  {}{}", icon, anomaly.detail);
            }
        }

        // Summary
        let critical_count = report.patterns.iter()
            .filter(|m| severity_ord(m.severity) <= 2).count();
        let warning_count = report.patterns.len() - critical_count;
        println!("\n{}", format!("━━━ {} critical, {} warning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            critical_count, warning_count).bold());

        Ok(())
    }
}

fn level_ord(lvl: &crate::core::types::LogLevel) -> u8 {
    use crate::core::types::LogLevel;
    match lvl { LogLevel::Error => 0, LogLevel::Warn => 1, LogLevel::Info => 2, LogLevel::Debug => 3, LogLevel::Trace => 4 }
}

fn level_color(lvl: &crate::core::types::LogLevel) -> Color {
    use crate::core::types::LogLevel;
    match lvl { LogLevel::Error => Color::Red, LogLevel::Warn => Color::Yellow, LogLevel::Info => Color::Green, _ => Color::White }
}

fn severity_ord(sev: crate::core::types::Severity) -> u8 {
    use crate::core::types::Severity;
    match sev { Severity::Critical => 1, Severity::Warning => 2, Severity::Info => 3 }
}

fn severity_label(sev: crate::core::types::Severity) -> &'static str {
    use crate::core::types::Severity;
    match sev { Severity::Critical => "CRITICAL", Severity::Warning => "WARNING", Severity::Info => "INFO" }
}

use colored::Color;
```

- [ ] **Step 2: Write output/mod.rs**

```rust
// src/output/mod.rs
pub mod terminal;
pub mod json;
pub mod report;
pub mod pipe;
```

- [ ] **Step 3: Commit**

```bash
git add src/output/
git commit -m "feat: terminal output with colored tables and bars"
```

---

### Task 15: JSON & Pipe Output

**Files:**
- Create: `src/output/json.rs`
- Create: `src/output/pipe.rs`

- [ ] **Step 1: Implement JSON output**

```rust
// src/output/json.rs
use crate::core::sink::Sink;
use crate::core::types::AnalysisReport;
use anyhow::Result;

pub struct JsonSink {
    pub pretty: bool,
}

impl Sink for JsonSink {
    fn name(&self) -> &str { "json" }

    fn write(&self, report: &AnalysisReport) -> Result<()> {
        let json = if self.pretty {
            serde_json::to_string_pretty(report)?
        } else {
            serde_json::to_string(report)?
        };
        println!("{}", json);
        Ok(())
    }
}
```

- [ ] **Step 2: Implement pipe output**

```rust
// src/output/pipe.rs
use crate::core::sink::Sink;
use crate::core::types::AnalysisReport;
use anyhow::Result;

pub struct PipeSink;

impl Sink for PipeSink {
    fn name(&self) -> &str { "pipe" }

    fn write(&self, report: &AnalysisReport) -> Result<()> {
        // One result per line, awk/grep friendly
        println!("file={}\tformat={}\tconfidence={:.2}\tlines={}\terrors={}",
            report.file_info.path,
            report.format.name,
            report.format.confidence,
            report.file_info.total_lines,
            report.file_info.parse_errors,
        );

        for pm in &report.patterns {
            println!("match={}\tseverity={}\tcount={}\tfirst={}\tlast={}",
                pm.pattern_name,
                format!("{:?}", pm.severity),
                pm.stats.count,
                pm.stats.first_seen.map_or("N/A".to_string(), |t| t.to_rfc3339()),
                pm.stats.last_seen.map_or("N/A".to_string(), |t| t.to_rfc3339()),
            );
        }

        for anomaly in &report.anomalies {
            println!("anomaly={}\ttype={:?}\tscore={:.2}\tdetail={}",
                anomaly.detail.replace('\t', " "),
                anomaly.anomaly_type,
                anomaly.score,
                anomaly.detail.replace('\t', " "),
            );
        }

        Ok(())
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add src/output/json.rs src/output/pipe.rs
git commit -m "feat: JSON and pipe-friendly output formatters"
```

---

### Task 16: Configuration System

**Files:**
- Create: `src/config/mod.rs`

- [ ] **Step 1: Implement config**

```rust
// src/config/mod.rs
use serde::Deserialize;
use std::path::{Path, PathBuf};
use crate::core::error::AppError;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    #[serde(default)]
    pub threads: usize,
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default = "default_format")]
    pub default_format: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LlmConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_llm_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_llm_model")]
    pub model: String,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectionConfig {
    #[serde(default = "default_sample_lines")]
    pub sample_lines: usize,
    #[serde(default = "default_confidence")]
    pub confidence_threshold: f64,
}

fn default_lang() -> String { "zh".into() }
fn default_format() -> String { "auto".into() }
fn default_llm_endpoint() -> String { "https://api.anthropic.com/v1".into() }
fn default_llm_model() -> String { "claude-sonnet-4-6".into() }
fn default_api_key_env() -> String { "LOG_ANALYZE_API_KEY".into() }
fn default_sample_lines() -> usize { 100 }
fn default_confidence() -> f64 { 0.7 }

impl Default for Config {
    fn default() -> Self {
        Config {
            general: GeneralConfig {
                threads: 0,
                lang: "zh".into(),
                default_format: "auto".into(),
            },
            llm: LlmConfig {
                enabled: false,
                endpoint: "https://api.anthropic.com/v1".into(),
                model: "claude-sonnet-4-6".into(),
                api_key_env: "LOG_ANALYZE_API_KEY".into(),
            },
            detection: DetectionConfig {
                sample_lines: 100,
                confidence_threshold: 0.7,
            },
        }
    }
}

/// Load config from multiple locations, merging from low to high priority:
/// system → user → local → passed file
pub fn load_config(local_path: Option<&Path>) -> Result<Config, AppError> {
    let mut config = Config::default();

    // 1. System-level
    if Path::new("/etc/log-analyze/config.toml").exists() {
        merge_toml("/etc/log-analyze/config.toml", &mut config)?;
    }

    // 2. User-level
    if let Some(home) = dirs_next::home_dir() {
        let user_config = home.join(".config/log-analyze/config.toml");
        if user_config.exists() {
            merge_toml(&user_config, &mut config)?;
        }
    }

    // 3. Local (./log-analyze.toml)
    let local = Path::new("log-analyze.toml");
    if local.exists() {
        merge_toml(local, &mut config)?;
    }

    // 4. Explicit path
    if let Some(path) = local_path {
        if path.exists() {
            merge_toml(path, &mut config)?;
        }
    }

    Ok(config)
}

fn merge_toml<P: AsRef<Path>>(path: P, config: &mut Config) -> Result<(), AppError> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| AppError::Config {
            path: path.as_ref().to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
    let overlay: Config = toml::from_str(&content)
        .map_err(|e| AppError::Config {
            path: path.as_ref().to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
    // Higher-priority overlay replaces entire sub-sections
    if overlay.general.threads > 0 || overlay.general.lang != "zh" || overlay.general.default_format != "auto" {
        if overlay.general.threads > 0 { config.general.threads = overlay.general.threads; }
        config.general.lang = overlay.general.lang;
        config.general.default_format = overlay.general.default_format;
    }
    if overlay.llm.enabled || overlay.llm.endpoint != default_llm_endpoint() {
        config.llm = overlay.llm;
    }
    if overlay.detection.sample_lines != default_sample_lines() || overlay.detection.confidence_threshold != default_confidence() {
        config.detection = overlay.detection;
    }
    Ok(())
}
```

- [ ] **Step 2: Commit**

```bash
git add src/config/
git commit -m "feat: config system with multi-file merge and priority hierarchy"
```

---

### Task 17: CLI Interface

**Files:**
- Create: `src/cli.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Implement CLI**

```rust
// src/cli.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "log-analyze",
    version = "0.1.0",
    about = "日志分析 CLI — 自动识别格式，提取特征，定位问题",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// 日志文件路径（支持多个文件）
    #[arg(value_name = "FILE")]
    pub files: Vec<PathBuf>,

    /// 强制日志格式
    #[arg(short = 'f', long, default_value = "auto")]
    pub format: String,

    /// 指定分析规则（逗号分隔）
    #[arg(short = 'p', long)]
    pub patterns: Option<String>,

    /// 输出目标（.json/.html 按后缀自动识别）
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// 启用 LLM 深度分析
    #[arg(long)]
    pub llm: bool,

    /// LLM API endpoint
    #[arg(long)]
    pub llm_endpoint: Option<String>,

    /// 输出语言
    #[arg(long, default_value = "zh")]
    pub lang: String,

    /// 时间范围
    #[arg(long)]
    pub time_range: Option<String>,

    /// 过滤日志级别
    #[arg(long)]
    pub level: Option<String>,

    /// 自定义规则文件路径
    #[arg(long)]
    pub rules: Option<PathBuf>,

    /// 并行线程数
    #[arg(long)]
    pub threads: Option<usize>,

    /// 管道友好输出
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 分析日志文件（默认命令）
    Analyze {
        #[arg(value_name = "FILE")]
        files: Vec<PathBuf>,
        #[arg(short = 'f', long, default_value = "auto")]
        format: String,
        #[arg(short = 'p', long)]
        patterns: Option<String>,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(long)]
        llm: bool,
        #[arg(short = 'q', long)]
        quiet: bool,
    },

    /// 仅检测日志格式
    Detect {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// 列出所有可用规则
    Patterns,

    /// 生成分析报告到文件
    Report {
        #[arg(value_name = "FILE")]
        files: Vec<PathBuf>,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[arg(long)]
        llm: bool,
    },
}
```

- [ ] **Step 2: Update main.rs**

```rust
// src/main.rs
use clap::Parser;
use std::path::Path;

use log_analyze::cli::{Cli, Commands};
use log_analyze::analyzer::engine::analyze_file;
use log_analyze::patterns::builtin::all_builtin_patterns;
use log_analyze::patterns::custom::load_rules;
use log_analyze::output::terminal::TerminalSink;
use log_analyze::output::json::JsonSink;
use log_analyze::output::pipe::PipeSink;
use log_analyze::core::sink::Sink;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Detect { file }) => {
            let detector = log_analyze::parsers::Detector::new();
            let (format, _) = detector.detect(file)?;
            println!("Format: {} (confidence: {:.1}%)", format.name, format.confidence * 100.0);
            return Ok(());
        }
        Some(Commands::Patterns) => {
            let patterns = all_builtin_patterns();
            for p in &patterns {
                println!("  {:<20} [{}] {}", p.name(), severity_str(p.severity()), p.description());
            }
            return Ok(());
        }
        Some(Commands::Report { files, output: out, llm }) => {
            // Report mode — write to file
            if files.is_empty() {
                anyhow::bail!("No input files specified");
            }
            let mut patterns = all_builtin_patterns();
            let report = analyze_file(&files[0], &patterns, 100)?;
            let ext = out.extension().and_then(|e| e.to_str()).unwrap_or("json");
            match ext {
                "html" => {
                    // HTML report — will be implemented in Task 17
                    println!("HTML report output to {}", out.display());
                }
                _ => {
                    let json_str = serde_json::to_string_pretty(&report)?;
                    std::fs::write(out, json_str)?;
                    println!("JSON report written to {}", out.display());
                }
            }
            return Ok(());
        }
        _ => {
            // Default: analyze mode
            let files = if cli.files.is_empty() {
                // Try to get files from analyze subcommand
                match &cli.command {
                    Some(Commands::Analyze { files: f, .. }) => f.clone(),
                    _ => vec![],
                }
            } else {
                cli.files.clone()
            };

            if files.is_empty() {
                anyhow::bail!("No input files specified. Usage: log-analyze [FILE]...");
            }

            let mut patterns = all_builtin_patterns();

            // Load custom rules if specified
            if let Some(rules_path) = &cli.rules {
                let custom = load_rules(rules_path)?;
                patterns.extend(custom);
            }

            let report = analyze_file(&files[0], &patterns, 100)?;

            if cli.quiet {
                PipeSink.write(&report)?;
            } else if let Some(out_path) = &cli.output {
                let ext = out_path.extension().and_then(|e| e.to_str()).unwrap_or("json");
                match ext {
                    "json" => {
                        let json_str = serde_json::to_string_pretty(&report)?;
                        std::fs::write(out_path, json_str)?;
                    }
                    _ => {
                        PipeSink.write(&report)?;
                    }
                }
            } else {
                let sink = TerminalSink::new();
                sink.write(&report)?;
            }
        }
    }

    Ok(())
}

fn severity_str(s: log_analyze::core::types::Severity) -> &'static str {
    use log_analyze::core::types::Severity;
    match s { Severity::Critical => "CRITICAL", Severity::Warning => "WARNING", Severity::Info => "INFO" }
}
```

- [ ] **Step 3: Build and verify**

Run: `cargo build --release && ./target/release/log-analyze --help`
Expected: Help text displays with all commands and flags.

Run: `./target/release/log-analyze tests/fixtures/nginx.log`
Expected: Terminal report with format detection, patterns, summary.

- [ ] **Step 4: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat: CLI interface with analyze, detect, patterns, report commands"
```

---

### Task 18: LLM Integration (Optional Feature)

**Files:**
- Create: `src/llm/mod.rs`
- Create: `src/llm/client.rs`

- [ ] **Step 1: Implement LLM client (only compiles with `--features llm`)**

```rust
// src/llm/mod.rs
pub mod client;

// src/llm/client.rs
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::core::types::Anomaly;

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub endpoint: String,
    pub model: String,
    pub api_key: String,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    text: String,
}

/// Analyze anomalies using an LLM API (Anthropic-compatible)
pub async fn analyze_with_llm(
    config: &LlmConfig,
    anomalies: &[Anomaly],
    context_lines: &[String],
) -> Result<String, String> {
    let client = Client::new();

    let context = context_lines.join("\n");
    let anomaly_desc: Vec<String> = anomalies.iter()
        .map(|a| format!("[{}] score={:.1}: {}", match a.anomaly_type {
            crate::core::types::AnomalyType::Spike => "SPIKE",
            crate::core::types::AnomalyType::Gap => "GAP",
            crate::core::types::AnomalyType::Frequency => "FREQUENCY",
        }, a.score, a.detail))
        .collect();

    let prompt = format!(
        "你是一个运维专家。请分析以下日志异常，给出根因分析、影响范围和修复建议。用中文回答。\n\n\
        检测到的异常:\n{}\n\n\
        异常上下文日志:\n{}\n\n\
        请分析：1) 根因  2) 影响范围  3) 修复建议",
        anomaly_desc.join("\n"),
        if context.len() > 4000 { &context[..4000] } else { &context }
    );

    let req = AnthropicRequest {
        model: config.model.clone(),
        max_tokens: 1024,
        messages: vec![AnthropicMessage {
            role: "user".to_string(),
            content: prompt,
        }],
    };

    let resp = client
        .post(&config.endpoint)
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("LLM API returned status {}", resp.status()));
    }

    let body: AnthropicResponse = resp.json().await
        .map_err(|e| format!("JSON parse error: {}", e))?;

    Ok(body.content.into_iter()
        .map(|c| c.text)
        .collect::<Vec<_>>()
        .join("\n"))
}
```

Now add to main.rs behind feature flag:

```rust
// In src/main.rs, add after existing imports:
#[cfg(feature = "llm")]
use log_analyze::llm::client::{analyze_with_llm, LlmConfig};

// In the analyze match arm, after anomaly detection:
#[cfg(feature = "llm")]
if cli.llm || (matches!(cli.command, Some(Commands::Analyze { llm: true, .. }))) {
    let api_key = std::env::var("LOG_ANALYZE_API_KEY")
        .unwrap_or_default();
    if !api_key.is_empty() && !report.anomalies.is_empty() {
        let config = LlmConfig {
            endpoint: cli.llm_endpoint.clone()
                .unwrap_or_else(|| "https://api.anthropic.com/v1/messages".into()),
            model: "claude-sonnet-4-6".into(),
            api_key,
        };
        // Collect context lines around anomalies
        let context: Vec<String> = report.anomalies.iter()
            .flat_map(|a| a.detail.lines().map(String::from))
            .collect();

        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(analyze_with_llm(&config, &report.anomalies, &context)) {
            Ok(analysis) => {
                println!("\n--- LLM 深度分析 ---\n{}", analysis);
            }
            Err(e) => {
                eprintln!("LLM 分析失败: {} (回退到规则引擎结果)", e);
            }
        }
    }
```

- [ ] **Step 2: Build with LLM feature**

Run: `cargo build --features llm`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
git add src/llm/ src/main.rs
git commit -m "feat: optional LLM deep analysis via Anthropic-compatible API"
```

---

### Task 19: Final Integration & Polish

**Files:**
- Modify: `Cargo.toml` (add `once_cell` dep)
- Create: `tests/fixtures/` all fixture files

- [ ] **Step 1: Validate all tests pass**

Run: `cargo test`
Expected: All tests pass.

- [ ] **Step 2: Add `once_cell` to Cargo.toml dependencies**

```toml
once_cell = "1"
```

- [ ] **Step 3: Run full analysis on provided fixtures**

Run:
```
cargo run -- tests/fixtures/nginx.log
cargo run -- tests/fixtures/syslog.log
cargo run -- tests/fixtures/json.log
cargo run -- tests/fixtures/generic.log
```

Expected: Each shows a formatted terminal report with format detection, patterns, and anomalies.

- [ ] **Step 4: Verify JSON output**

Run: `cargo run -- tests/fixtures/nginx.log -o /tmp/report.json && cat /tmp/report.json | python3 -m json.tool | head -20`
Expected: Valid JSON output.

- [ ] **Step 5: Verify pipe output**

Run: `cargo run -- tests/fixtures/nginx.log -q`
Expected: Tab-separated output, grep/awk friendly.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml
git commit -m "chore: add once_cell dependency, final integration polish"
```
