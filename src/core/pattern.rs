use crate::core::types::{LogEntry, PatternMatch, Severity};

pub trait Pattern: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> Severity;
    fn check(&self, entry: &LogEntry) -> bool;
    fn min_count(&self) -> u64 { 1 }

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
