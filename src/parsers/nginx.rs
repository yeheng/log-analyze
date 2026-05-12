use std::collections::HashMap;
use std::str;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::parser::LogParser;
use crate::core::types::{FieldValue, LogEntry, LogLevel};

// Nginx combined log format:
// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
static NGINX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$"#,
    )
    .unwrap()
});

fn parse_nginx_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
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

pub struct NginxParser;

impl LogParser for NginxParser {
    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let line = str::from_utf8(raw).ok()?.trim();
        let caps = NGINX_RE.captures(line)?;

        let remote_addr = caps.get(1)?.as_str();
        let remote_user = caps.get(2)?.as_str();
        let ts_str = caps.get(3)?.as_str();
        let request = caps.get(4)?.as_str();
        let status: u16 = caps.get(5)?.as_str().parse().ok()?;
        let body_bytes: u64 = caps.get(6)?.as_str().parse().ok()?;
        let referer = caps.get(7)?.as_str();
        let user_agent = caps.get(8)?.as_str();

        let timestamp = parse_nginx_timestamp(ts_str);
        let level = status_to_level(status);

        let mut fields = HashMap::new();
        fields.insert("remote_addr".to_string(), FieldValue::String(remote_addr.to_string()));
        fields.insert("remote_user".to_string(), FieldValue::String(remote_user.to_string()));
        fields.insert("request".to_string(), FieldValue::String(request.to_string()));
        fields.insert("status".to_string(), FieldValue::Number(status as f64));
        fields.insert("body_bytes_sent".to_string(), FieldValue::Number(body_bytes as f64));
        fields.insert("http_referer".to_string(), FieldValue::String(referer.to_string()));
        fields.insert("http_user_agent".to_string(), FieldValue::String(user_agent.to_string()));

        Some(LogEntry {
            timestamp,
            level: Some(level),
            source: Some("nginx".to_string()),
            message: request.to_string(),
            fields,
            line_number,
        })
    }

    fn name(&self) -> &str {
        "nginx"
    }

    fn supports_level(&self) -> bool {
        false
    }

    fn supports_timestamp(&self) -> bool {
        true
    }
}
