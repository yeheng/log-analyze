use crate::core::types::LogEntry;

pub trait LogParser: Send + Sync {
    fn parse(&self, raw: &[u8], line_number: u64) -> Option<LogEntry>;
    fn name(&self) -> &str;
    fn supports_level(&self) -> bool;
    fn supports_timestamp(&self) -> bool;
}

pub struct ParsedChunk {
    pub entries: Vec<LogEntry>,
    pub errors: u64,
}
