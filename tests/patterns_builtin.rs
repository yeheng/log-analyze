use std::collections::HashMap;

use log_analyze::core::pattern::Pattern;
use log_analyze::core::types::{LogEntry, LogLevel, Severity};
use log_analyze::patterns::builtin::{
    all_builtin_patterns, ConnectionRefusedPattern, OomKillPattern, StackTracePattern,
    TimeoutPattern,
};

fn make_entry(message: &str) -> LogEntry {
    LogEntry {
        timestamp: None,
        level: Some(LogLevel::Error),
        source: None,
        message: message.to_string(),
        fields: HashMap::new(),
        line_number: 1,
    }
}

#[test]
fn test_oom_kill_pattern() {
    let pat = OomKillPattern::new();
    assert_eq!(pat.name(), "OomKill");
    assert_eq!(pat.severity(), Severity::Critical);

    assert!(pat.check(&make_entry("Out of memory: kill process 1234")));
    assert!(pat.check(&make_entry("oom-kill: task nginx killed")));
    assert!(pat.check(&make_entry("OOM Kill invoked")));
    assert!(pat.check(&make_entry("Killed process 5678 (java)")));
    assert!(pat.check(&make_entry("oom reaper: reaped process")));

    assert!(!pat.check(&make_entry("normal log message")));
    assert!(!pat.check(&make_entry("memory usage is fine")));
}

#[test]
fn test_connection_refused_pattern() {
    let pat = ConnectionRefusedPattern::new();
    assert_eq!(pat.name(), "ConnectionRefused");
    assert_eq!(pat.severity(), Severity::Critical);

    assert!(pat.check(&make_entry("Connection refused to 10.0.0.1:5432")));
    assert!(pat.check(&make_entry("ECONNREFUSED 127.0.0.1:8080")));
    assert!(pat.check(&make_entry("connect_refused error")));

    assert!(!pat.check(&make_entry("connection established")));
    assert!(!pat.check(&make_entry("normal message")));
}

#[test]
fn test_timeout_pattern() {
    let pat = TimeoutPattern::new();
    assert_eq!(pat.name(), "Timeout");
    assert_eq!(pat.severity(), Severity::Warning);

    assert!(pat.check(&make_entry("Connection timeout after 30s")));
    assert!(pat.check(&make_entry("Request timed out")));
    assert!(pat.check(&make_entry("ETIMEDOUT")));
    assert!(pat.check(&make_entry("deadline exceeded for RPC")));

    assert!(!pat.check(&make_entry("completed in 5ms")));
    assert!(!pat.check(&make_entry("normal log")));
}

#[test]
fn test_stack_trace_pattern() {
    let pat = StackTracePattern::new();
    assert_eq!(pat.name(), "StackTrace");
    assert_eq!(pat.severity(), Severity::Critical);

    assert!(pat.check(&make_entry("java.lang.NullPointerException")));
    assert!(pat.check(&make_entry("  at com.example.Handler.process(Handler.java:42)")));
    assert!(pat.check(&make_entry("Traceback (most recent call last):")));
    assert!(pat.check(&make_entry("stack trace:")));
    assert!(pat.check(&make_entry("Error: something went wrong")));

    assert!(!pat.check(&make_entry("normal log message")));
    assert!(!pat.check(&make_entry("processing request at server")));
}

#[test]
fn test_all_builtin_patterns_count() {
    let patterns = all_builtin_patterns();
    assert_eq!(patterns.len(), 6);
}

#[test]
fn test_all_builtin_patterns_names_unique() {
    let patterns = all_builtin_patterns();
    let names: Vec<&str> = patterns.iter().map(|p| p.name()).collect();
    for i in 0..names.len() {
        for j in (i + 1)..names.len() {
            assert_ne!(names[i], names[j], "duplicate pattern name: {}", names[i]);
        }
    }
}

#[test]
fn test_oom_kill_min_count() {
    let pat = OomKillPattern::new();
    assert_eq!(pat.min_count(), 1);
}
