use crate::core::types::AnalysisReport;
use anyhow::Result;

pub trait Sink: Send + Sync {
    fn write(&self, report: &AnalysisReport) -> Result<()>;
    fn name(&self) -> &str;
}
