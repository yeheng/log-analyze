use std::collections::HashMap;
use std::str;

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::parser::LogParser;
use crate::core::types::{FieldValue, LogEntry, LogLevel};

// RFC 3164: <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
static SYSLOG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        ^(?:<(\d{1,3})>)?                    # PRI (optional)
        (\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) # Timestamp: Mon DD HH:MM:SS
        \s+
        (\S+)                                 # Hostname
        \s+
        ([^\[:]+)                             # App name
        (?:\[(\d+)\])?                        # PID (optional)
        :\s*
        (.*)$                                 # Message
    ",
    )
    .unwrap()
});

fn pri_to_level(pri: u32) -> Option<LogLevel> {
    let severity = pri % 8;
    match severity {
        0 | 1 | 2 => Some(LogLevel::Error),  // emergency, alert, critical
        3 => Some(LogLevel::Error),           // error
        4 => Some(LogLevel::Warn),            // warning
        5 => Some(LogLevel::Info),            // notice
        6 => Some(LogLevel::Info),            // informational
        7 => Some(LogLevel::Debug),           // debug
        _ => None,
    }
}

fn parse_syslog_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    let year = now.year();
    let padded = format!("{} {}", year, ts_str);
    // Handle "Mon  5" vs "Mon 05" formats
    let normalized = regex::Regex::new(r"\s+")
        .unwrap()
        .replace_all(&padded, " ")
        .to_string();
    if let Ok(dt) = NaiveDateTime::parse_from_str(&normalized, "%Y %b %d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    None
}

pub struct SyslogParser;

impl LogParser for SyslogParser {
    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let line = str::from_utf8(raw).ok()?.trim();
        let caps = SYSLOG_RE.captures(line)?;

        let pri: Option<u32> = caps.get(1).and_then(|m| m.as_str().parse().ok());
        let ts_str = caps.get(2)?.as_str();
        let hostname = caps.get(3)?.as_str();
        let app = caps.get(4)?.as_str().trim();
        let pid: Option<&str> = caps.get(5).map(|m| m.as_str());
        let message = caps.get(6)?.as_str().to_string();

        let timestamp = parse_syslog_timestamp(ts_str);

        let level = pri.and_then(pri_to_level);

        let mut fields = HashMap::new();
        fields.insert("hostname".to_string(), FieldValue::String(hostname.to_string()));
        fields.insert("app".to_string(), FieldValue::String(app.to_string()));
        if let Some(p) = pid {
            fields.insert("pid".to_string(), FieldValue::String(p.to_string()));
        }
        if let Some(p) = pri {
            fields.insert("pri".to_string(), FieldValue::Number(p as f64));
        }

        Some(LogEntry {
            timestamp,
            level,
            source: Some(app.to_string()),
            message,
            fields,
            line_number,
        })
    }

    fn name(&self) -> &str {
        "syslog"
    }

    fn supports_level(&self) -> bool {
        true
    }

    fn supports_timestamp(&self) -> bool {
        true
    }
}
