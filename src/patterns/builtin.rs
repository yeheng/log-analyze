use crate::core::pattern::Pattern;
use crate::core::types::{LogEntry, Severity};
use regex::Regex;

// ---------------------------------------------------------------------------
// ConnectionRefusedPattern
// ---------------------------------------------------------------------------

pub struct ConnectionRefusedPattern {
    re: Regex,
}

impl ConnectionRefusedPattern {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(?i)(connection refused|ECONNREFUSED|connect_refused)").unwrap(),
        }
    }
}

impl Pattern for ConnectionRefusedPattern {
    fn name(&self) -> &str {
        "ConnectionRefused"
    }
    fn description(&self) -> &str {
        "Detects connection refused errors indicating service unavailability"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn check(&self, entry: &LogEntry) -> bool {
        self.re.is_match(&entry.message)
    }
    fn min_count(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// OomKillPattern
// ---------------------------------------------------------------------------

pub struct OomKillPattern {
    re: Regex,
}

impl OomKillPattern {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(?i)(out of memory|oom[-_ ]?kill|oom reaper|killed process)").unwrap(),
        }
    }
}

impl Pattern for OomKillPattern {
    fn name(&self) -> &str {
        "OomKill"
    }
    fn description(&self) -> &str {
        "Detects out-of-memory kill events"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn check(&self, entry: &LogEntry) -> bool {
        self.re.is_match(&entry.message)
    }
    fn min_count(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// DiskFullPattern
// ---------------------------------------------------------------------------

pub struct DiskFullPattern {
    re: Regex,
}

impl DiskFullPattern {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(?i)(no space left on device|disk full|ENOSPC)").unwrap(),
        }
    }
}

impl Pattern for DiskFullPattern {
    fn name(&self) -> &str {
        "DiskFull"
    }
    fn description(&self) -> &str {
        "Detects disk full / no space errors"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn check(&self, entry: &LogEntry) -> bool {
        self.re.is_match(&entry.message)
    }
    fn min_count(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// TimeoutPattern
// ---------------------------------------------------------------------------

pub struct TimeoutPattern {
    re: Regex,
}

impl TimeoutPattern {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(?i)(timeout|timed[- ]?out|ETIMEDOUT|deadline exceeded)").unwrap(),
        }
    }
}

impl Pattern for TimeoutPattern {
    fn name(&self) -> &str {
        "Timeout"
    }
    fn description(&self) -> &str {
        "Detects timeout errors"
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn check(&self, entry: &LogEntry) -> bool {
        self.re.is_match(&entry.message)
    }
    fn min_count(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// AuthFailurePattern
// ---------------------------------------------------------------------------

pub struct AuthFailurePattern {
    re: Regex,
}

impl AuthFailurePattern {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(?i)(authentication failure|auth.*fail|login.*fail|invalid credentials|access denied|Failed password)").unwrap(),
        }
    }
}

impl Pattern for AuthFailurePattern {
    fn name(&self) -> &str {
        "AuthFailure"
    }
    fn description(&self) -> &str {
        "Detects authentication and authorization failures"
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn check(&self, entry: &LogEntry) -> bool {
        self.re.is_match(&entry.message)
    }
    fn min_count(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// StackTracePattern
// ---------------------------------------------------------------------------

pub struct StackTracePattern {
    re: Regex,
}

impl StackTracePattern {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(?i)(at\s+\S+\([^)]*\)|Exception\b|Error:|Traceback \(most recent|stack trace:)").unwrap(),
        }
    }
}

impl Pattern for StackTracePattern {
    fn name(&self) -> &str {
        "StackTrace"
    }
    fn description(&self) -> &str {
        "Detects stack traces and exception dumps"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn check(&self, entry: &LogEntry) -> bool {
        self.re.is_match(&entry.message)
    }
    fn min_count(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

pub fn all_builtin_patterns() -> Vec<Box<dyn Pattern>> {
    vec![
        Box::new(ConnectionRefusedPattern::new()),
        Box::new(OomKillPattern::new()),
        Box::new(DiskFullPattern::new()),
        Box::new(TimeoutPattern::new()),
        Box::new(AuthFailurePattern::new()),
        Box::new(StackTracePattern::new()),
    ]
}
