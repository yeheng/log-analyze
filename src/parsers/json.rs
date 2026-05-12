use std::collections::HashMap;
use std::str;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::core::parser::LogParser;
use crate::core::types::{FieldValue, LogEntry, LogLevel};

fn find_field<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(v) = obj.get(*key) {
            return Some(v);
        }
    }
    None
}

fn extract_level(val: &Value) -> Option<LogLevel> {
    let s = val.as_str()?.to_uppercase();
    match s.as_str() {
        "ERROR" | "FATAL" | "SEVERE" | "CRITICAL" => Some(LogLevel::Error),
        "WARN" | "WARNING" => Some(LogLevel::Warn),
        "INFO" | "INFORMATION" | "NOTICE" => Some(LogLevel::Info),
        "DEBUG" | "FINE" | "FINER" | "FINEST" => Some(LogLevel::Debug),
        "TRACE" => Some(LogLevel::Trace),
        _ => {
            // Handle numeric levels
            if let Some(n) = val.as_u64() {
                return match n {
                    0..=2 => Some(LogLevel::Trace),
                    3..=4 => Some(LogLevel::Debug),
                    5..=6 => Some(LogLevel::Info),
                    7..=8 => Some(LogLevel::Warn),
                    _ => Some(LogLevel::Error),
                };
            }
            None
        }
    }
}

fn extract_timestamp(val: &Value) -> Option<DateTime<Utc>> {
    let s = val.as_str()?;

    // Try RFC 3339
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try common formats without timezone
    for fmt in &[
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
        }
    }

    // Unix epoch (seconds)
    if let Ok(n) = s.parse::<i64>() {
        return DateTime::from_timestamp(n, 0);
    }

    None
}

fn json_value_to_field(val: &Value) -> FieldValue {
    match val {
        Value::String(s) => FieldValue::String(s.clone()),
        Value::Number(n) => FieldValue::Number(n.as_f64().unwrap_or(0.0)),
        Value::Bool(b) => FieldValue::Boolean(*b),
        Value::Null => FieldValue::Null,
        Value::Array(_) | Value::Object(_) => FieldValue::String(val.to_string()),
    }
}

pub struct JsonParser;

impl LogParser for JsonParser {
    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry> {
        let line = str::from_utf8(raw).ok()?.trim();
        let obj: serde_json::Map<String, Value> = serde_json::from_str(line).ok()?;

        let level = find_field(&obj, &["level", "severity", "lvl", "loglevel", "level_name"])
            .and_then(|v| extract_level(v));

        let timestamp = find_field(&obj, &["timestamp", "time", "ts", "@timestamp", "datetime", "date"])
            .and_then(|v| extract_timestamp(v));

        let message = find_field(&obj, &["message", "msg", "text", "log"])
            .and_then(|v| v.as_str())
            .unwrap_or(line)
            .to_string();

        let source = find_field(&obj, &["source", "logger", "module", "component", "caller"])
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Skip known top-level fields; put the rest into `fields`
        let known_keys = [
            "level", "severity", "lvl", "loglevel", "level_name",
            "timestamp", "time", "ts", "@timestamp", "datetime", "date",
            "message", "msg", "text", "log",
            "source", "logger", "module", "component", "caller",
        ];

        let fields: HashMap<String, FieldValue> = obj
            .iter()
            .filter(|(k, _)| !known_keys.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), json_value_to_field(v)))
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

    fn name(&self) -> &str {
        "json"
    }

    fn supports_level(&self) -> bool {
        true
    }

    fn supports_timestamp(&self) -> bool {
        true
    }
}
