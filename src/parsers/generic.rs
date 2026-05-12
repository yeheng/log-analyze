use std::collections::HashMap;
use std::str;

use chrono::{DateTime, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::parser::LogParser;
use crate::core::types::{LogEntry, LogLevel};

static LEVEL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(ERROR|WARN(?:ING)?|INFO(?:RMATION)?|DEBUG|TRACE(?:\(.*?\))?)\b",
    )
    .unwrap()
});

static TIMESTAMP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        (?:
            \d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?
            |
            \d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}
            |
            \d{2}:\d{2}:\d{2}(?:\.\d+)?
        )",
    )
    .unwrap()
});

static BRACKET_TS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]")
        .unwrap()
});

fn parse_level(raw_level: &str) -> Option<LogLevel> {
    match raw_level.to_uppercase() {
        s if s.starts_with("ERROR") => Some(LogLevel::Error),
        s if s.starts_with("WARN") || s.starts_with("WARNING") => Some(LogLevel::Warn),
        s if s.starts_with("INFO") || s.starts_with("INFORMATION") => Some(LogLevel::Info),
        s if s.starts_with("DEBUG") => Some(LogLevel::Debug),
        s if s.starts_with("TRACE") => Some(LogLevel::Trace),
        _ => None,
    }
}

fn parse_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
    // ISO 8601 with timezone
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts_str) {
        return Some(dt.with_timezone(&Utc));
    }

    // ISO 8601 without timezone (treat as UTC)
    if let Ok(dt) = NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }

    // MM/DD/YYYY HH:MM:SS
    if let Ok(dt) = NaiveDateTime::parse_from_str(ts_str, "%m/%d/%Y %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }

    None
}

pub fn parse_line(raw: &[u8], line_number: u64) -> LogEntry {
    let line = match str::from_utf8(raw) {
        Ok(s) => s.trim(),
        Err(_) => {
            return LogEntry {
                timestamp: None,
                level: None,
                source: None,
                message: String::from_utf8_lossy(raw).into_owned(),
                fields: HashMap::new(),
                line_number,
            };
        }
    };

    let level = LEVEL_RE
        .captures(line)
        .and_then(|caps| caps.get(1))
        .and_then(|m| parse_level(m.as_str()));

    let timestamp = BRACKET_TS_RE
        .captures(line)
        .and_then(|caps| caps.get(1))
        .and_then(|m| parse_timestamp(m.as_str()))
        .or_else(|| {
            TIMESTAMP_RE
                .find(line)
                .and_then(|m| parse_timestamp(m.as_str()))
        });

    LogEntry {
        timestamp,
        level,
        source: None,
        message: line.to_string(),
        fields: HashMap::new(),
        line_number,
    }
}

pub struct GenericParser;

impl LogParser for GenericParser {
    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        Some(parse_line(raw, line_number))
    }

    fn name(&self) -> &str {
        "generic"
    }

    fn supports_level(&self) -> bool {
        true
    }

    fn supports_timestamp(&self) -> bool {
        true
    }
}
