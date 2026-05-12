use std::collections::HashMap;
use std::str;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::parser::LogParser;
use crate::core::types::{FieldValue, LogEntry, LogLevel};

// Apache Common Log Format:
// $remote_addr $remote_ident $remote_user [$time] "$request" $status $response_size
static APACHE_CLF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)$"#,
    )
    .unwrap()
});

// Apache Combined Log Format (adds referer + user-agent)
static APACHE_COMBINED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"$"#,
    )
    .unwrap()
});

fn parse_apache_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
    // Format: 12/May/2026:10:30:45 +0000
    DateTime::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

fn status_to_level(status: u16) -> LogLevel {
    match status {
        200..=399 => LogLevel::Info,
        400..=499 => LogLevel::Warn,
        _ => LogLevel::Error,
    }
}

pub struct ApacheParser;

impl LogParser for ApacheParser {
    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let line = str::from_utf8(raw).ok()?.trim();

        // Try combined first (more specific), fall back to CLF
        if let Some(caps) = APACHE_COMBINED_RE.captures(line) {
            let remote_addr = caps.get(1)?.as_str();
            let ident = caps.get(2)?.as_str();
            let remote_user = caps.get(3)?.as_str();
            let ts_str = caps.get(4)?.as_str();
            let request = caps.get(5)?.as_str();
            let status: u16 = caps.get(6)?.as_str().parse().ok()?;
            let size_str = caps.get(7)?.as_str();
            let referer = caps.get(8)?.as_str();
            let user_agent = caps.get(9)?.as_str();

            let timestamp = parse_apache_timestamp(ts_str);
            let level = status_to_level(status);

            let mut fields = HashMap::new();
            fields.insert("remote_addr".to_string(), FieldValue::String(remote_addr.to_string()));
            fields.insert("ident".to_string(), FieldValue::String(ident.to_string()));
            fields.insert("remote_user".to_string(), FieldValue::String(remote_user.to_string()));
            fields.insert("request".to_string(), FieldValue::String(request.to_string()));
            fields.insert("status".to_string(), FieldValue::Number(status as f64));
            let size: f64 = if size_str == "-" { 0.0 } else { size_str.parse().unwrap_or(0.0) };
            fields.insert("response_size".to_string(), FieldValue::Number(size));
            fields.insert("http_referer".to_string(), FieldValue::String(referer.to_string()));
            fields.insert("http_user_agent".to_string(), FieldValue::String(user_agent.to_string()));

            return Some(LogEntry {
                timestamp,
                level: Some(level),
                source: Some("apache".to_string()),
                message: request.to_string(),
                fields,
                line_number,
            });
        }

        // Fall back to Common Log Format
        let caps = APACHE_CLF_RE.captures(line)?;
        let remote_addr = caps.get(1)?.as_str();
        let ident = caps.get(2)?.as_str();
        let remote_user = caps.get(3)?.as_str();
        let ts_str = caps.get(4)?.as_str();
        let request = caps.get(5)?.as_str();
        let status: u16 = caps.get(6)?.as_str().parse().ok()?;
        let size_str = caps.get(7)?.as_str();

        let timestamp = parse_apache_timestamp(ts_str);
        let level = status_to_level(status);

        let mut fields = HashMap::new();
        fields.insert("remote_addr".to_string(), FieldValue::String(remote_addr.to_string()));
        fields.insert("ident".to_string(), FieldValue::String(ident.to_string()));
        fields.insert("remote_user".to_string(), FieldValue::String(remote_user.to_string()));
        fields.insert("request".to_string(), FieldValue::String(request.to_string()));
        fields.insert("status".to_string(), FieldValue::Number(status as f64));
        let size: f64 = if size_str == "-" { 0.0 } else { size_str.parse().unwrap_or(0.0) };
        fields.insert("response_size".to_string(), FieldValue::Number(size));

        Some(LogEntry {
            timestamp,
            level: Some(level),
            source: Some("apache".to_string()),
            message: request.to_string(),
            fields,
            line_number,
        })
    }

    fn name(&self) -> &str {
        "apache"
    }

    fn supports_level(&self) -> bool {
        false
    }

    fn supports_timestamp(&self) -> bool {
        true
    }
}
