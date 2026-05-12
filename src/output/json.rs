use anyhow::Result;

use crate::core::sink::Sink;
use crate::core::types::AnalysisReport;

pub struct JsonSink;

impl Sink for JsonSink {
    fn write(&self, report: &AnalysisReport) -> Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        println!("{}", json);
        Ok(())
    }

    fn name(&self) -> &str {
        "json"
    }
}
