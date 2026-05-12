use log_analyze::core::parser::LogParser;
use log_analyze::core::types::{FieldValue, LogLevel};
use log_analyze::parsers::generic::{self, GenericParser};
use log_analyze::parsers::json::JsonParser;
use log_analyze::parsers::syslog::SyslogParser;
use log_analyze::parsers::nginx::NginxParser;
use log_analyze::parsers::apache::ApacheParser;

// --- GenericParser tests ---

#[test]
fn generic_parses_error_level() {
    let line = b"2026-05-12 10:30:00 ERROR Something went wrong";
    let entry = generic::parse_line(line, 1);
    assert_eq!(entry.level, Some(LogLevel::Error));
    assert_eq!(entry.line_number, 1);
}

#[test]
fn generic_parses_warn_level() {
    let line = b"2026-05-12 10:30:00 WARN Cache miss";
    let entry = generic::parse_line(line, 2);
    assert_eq!(entry.level, Some(LogLevel::Warn));
}

#[test]
fn generic_parses_info_level() {
    let line = b"2026-05-12 10:30:00 INFO Request OK";
    let entry = generic::parse_line(line, 3);
    assert_eq!(entry.level, Some(LogLevel::Info));
}

#[test]
fn generic_parses_debug_level() {
    let line = b"2026-05-12 10:30:00 DEBUG Query result";
    let entry = generic::parse_line(line, 4);
    assert_eq!(entry.level, Some(LogLevel::Debug));
}

#[test]
fn generic_parses_trace_level() {
    let line = b"2026-05-12 10:30:00 TRACE(inner) entering function";
    let entry = generic::parse_line(line, 5);
    assert_eq!(entry.level, Some(LogLevel::Trace));
}

#[test]
fn generic_parses_timestamp_with_t_separator() {
    let line = b"2026-05-12T10:30:00Z INFO message";
    let entry = generic::parse_line(line, 1);
    assert!(entry.timestamp.is_some());
    let ts = entry.timestamp.unwrap();
    assert_eq!(ts.format("%Y-%m-%d").to_string(), "2026-05-12");
}

#[test]
fn generic_parses_timestamp_with_space_separator() {
    let line = b"2026-05-12 10:30:00 INFO message";
    let entry = generic::parse_line(line, 1);
    assert!(entry.timestamp.is_some());
}

#[test]
fn generic_parses_bracket_timestamp() {
    let line = b"INFO [2026-05-12T10:30:00+00:00] message here";
    let entry = generic::parse_line(line, 1);
    assert!(entry.timestamp.is_some());
}

#[test]
fn generic_no_level_returns_none() {
    let line = b"just a plain message without level";
    let entry = generic::parse_line(line, 1);
    assert!(entry.level.is_none());
}

#[test]
fn generic_parser_trait_impl() {
    let parser = GenericParser;
    assert_eq!(parser.name(), "generic");
    assert!(parser.supports_level());
    assert!(parser.supports_timestamp());

    let result = parser.parse(b"2026-05-12 10:30:00 ERROR test", 1);
    assert!(result.is_some());
    let entry = result.unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
}

// --- JsonParser tests ---

#[test]
fn json_parses_standard_fields() {
    let parser = JsonParser;
    let line = br#"{"timestamp":"2026-05-12T10:30:00Z","level":"ERROR","message":"Failed login","source":"auth"}"#;
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.message, "Failed login");
    assert_eq!(entry.source, Some("auth".to_string()));
}

#[test]
fn json_parses_alternate_field_names() {
    let parser = JsonParser;
    let line = br#"{"ts":"2026-05-12T10:30:00Z","lvl":"warn","msg":"Cache miss","component":"cache"}"#;
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Warn));
    assert_eq!(entry.message, "Cache miss");
    assert_eq!(entry.source, Some("cache".to_string()));
}

#[test]
fn json_extracts_extra_fields() {
    let parser = JsonParser;
    let line = br#"{"level":"INFO","message":"test","request_id":"abc123","count":42}"#;
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.fields.get("request_id"), Some(&FieldValue::String("abc123".to_string())));
    assert_eq!(entry.fields.get("count"), Some(&FieldValue::Number(42.0)));
}

#[test]
fn json_returns_none_for_invalid() {
    let parser = JsonParser;
    assert!(parser.parse(b"not json at all", 1).is_none());
}

#[test]
fn json_handles_fatal_level() {
    let parser = JsonParser;
    let line = br#"{"level":"FATAL","message":"Out of memory"}"#;
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
}

#[test]
fn json_parser_trait() {
    let parser = JsonParser;
    assert_eq!(parser.name(), "json");
    assert!(parser.supports_level());
    assert!(parser.supports_timestamp());
}

// --- SyslogParser tests ---

#[test]
fn syslog_parses_with_pri() {
    let parser = SyslogParser;
    let line = b"<34>May 12 10:30:00 webserver sshd[1234]: Failed password for root";
    let entry = parser.parse(line, 1).unwrap();
    // PRI 34 = facility 4 (auth), severity 2 (critical) -> Error
    assert_eq!(entry.level, Some(LogLevel::Error));
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.source, Some("sshd".to_string()));
    assert!(entry.message.contains("Failed password"));
}

#[test]
fn syslog_parses_without_pri() {
    let parser = SyslogParser;
    let line = b"May 12 10:30:03 gateway haproxy[3456]: backend server web1 is UP";
    let entry = parser.parse(line, 1).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.source, Some("haproxy".to_string()));
    // Without PRI, level is None
    assert!(entry.level.is_none());
}

#[test]
fn syslog_extracts_fields() {
    let parser = SyslogParser;
    let line = b"<34>May 12 10:30:00 webserver sshd[1234]: Authentication failure";
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.fields.get("hostname"), Some(&FieldValue::String("webserver".to_string())));
    assert_eq!(entry.fields.get("pid"), Some(&FieldValue::String("1234".to_string())));
    assert_eq!(entry.fields.get("pri"), Some(&FieldValue::Number(34.0)));
}

#[test]
fn syslog_returns_none_for_garbage() {
    let parser = SyslogParser;
    assert!(parser.parse(b"not syslog format", 1).is_none());
}

#[test]
fn syslog_parser_trait() {
    let parser = SyslogParser;
    assert_eq!(parser.name(), "syslog");
    assert!(parser.supports_level());
    assert!(parser.supports_timestamp());
}

// --- NginxParser tests ---

#[test]
fn nginx_parses_combined_format() {
    let parser = NginxParser;
    let line = br#"192.168.1.1 - admin [12/May/2026:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0""#;
    let entry = parser.parse(line, 1).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.level, Some(LogLevel::Info)); // 200
    assert_eq!(entry.source, Some("nginx".to_string()));
    assert!(entry.message.contains("GET /api/users"));
    assert_eq!(entry.fields.get("status"), Some(&FieldValue::Number(200.0)));
    assert_eq!(entry.fields.get("body_bytes_sent"), Some(&FieldValue::Number(1234.0)));
}

#[test]
fn nginx_classifies_404_as_warn() {
    let parser = NginxParser;
    let line = br#"10.0.0.2 - - [12/May/2026:10:30:03 +0000] "GET /missing HTTP/1.1" 404 128 "-" "Python-urllib/3.0""#;
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Warn));
}

#[test]
fn nginx_classifies_502_as_error() {
    let parser = NginxParser;
    let line = br#"192.168.1.100 - - [12/May/2026:10:30:04 +0000] "GET /api/health HTTP/1.1" 502 0 "-" "kube-probe/1.0""#;
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
}

#[test]
fn nginx_returns_none_for_invalid() {
    let parser = NginxParser;
    assert!(parser.parse(b"not nginx log", 1).is_none());
}

#[test]
fn nginx_parser_trait() {
    let parser = NginxParser;
    assert_eq!(parser.name(), "nginx");
    assert!(!parser.supports_level());
    assert!(parser.supports_timestamp());
}

// --- ApacheParser tests ---

#[test]
fn apache_parses_common_log_format() {
    let parser = ApacheParser;
    let line = b"192.168.1.1 - admin [12/May/2026:10:30:00 +0000] \"GET /index.html HTTP/1.1\" 200 2326";
    let entry = parser.parse(line, 1).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.level, Some(LogLevel::Info)); // 200
    assert_eq!(entry.source, Some("apache".to_string()));
    assert_eq!(entry.fields.get("status"), Some(&FieldValue::Number(200.0)));
}

#[test]
fn apache_parses_combined_format() {
    let parser = ApacheParser;
    let line = br#"192.168.1.1 - admin [12/May/2026:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 2326 "https://example.com/" "Mozilla/5.0""#;
    let entry = parser.parse(line, 1).unwrap();
    assert!(entry.timestamp.is_some());
    assert_eq!(entry.level, Some(LogLevel::Info));
    assert_eq!(entry.fields.get("http_referer"), Some(&FieldValue::String("https://example.com/".to_string())));
    assert_eq!(entry.fields.get("http_user_agent"), Some(&FieldValue::String("Mozilla/5.0".to_string())));
}

#[test]
fn apache_classifies_403_as_warn() {
    let parser = ApacheParser;
    let line = b"10.0.0.1 - - [12/May/2026:10:30:01 +0000] \"POST /login HTTP/1.1\" 403 512";
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Warn));
}

#[test]
fn apache_classifies_500_as_error() {
    let parser = ApacheParser;
    let line = b"192.168.1.100 - - [12/May/2026:10:30:04 +0000] \"GET /error HTTP/1.1\" 500 0";
    let entry = parser.parse(line, 1).unwrap();
    assert_eq!(entry.level, Some(LogLevel::Error));
}

#[test]
fn apache_returns_none_for_invalid() {
    let parser = ApacheParser;
    assert!(parser.parse(b"not apache log", 1).is_none());
}

#[test]
fn apache_parser_trait() {
    let parser = ApacheParser;
    assert_eq!(parser.name(), "apache");
    assert!(!parser.supports_level());
    assert!(parser.supports_timestamp());
}
