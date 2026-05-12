use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::core::error::AppError;
use crate::core::pattern::Pattern;
use crate::core::types::{FieldValue, LogEntry, Severity};

// ---------------------------------------------------------------------------
// TOML schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CustomRule {
    pub rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
pub struct RuleDef {
    pub name: String,
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_match_type")]
    pub match_type: MatchType,
    pub expression: Option<String>,
    pub field: Option<String>,
    pub condition: Option<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub count_threshold: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    Regex,
    Keyword,
    Field,
}

fn default_severity() -> Severity {
    Severity::Warning
}

fn default_match_type() -> MatchType {
    MatchType::Regex
}

// ---------------------------------------------------------------------------
// CustomPattern
// ---------------------------------------------------------------------------

pub struct CustomPattern {
    def: RuleDef,
    re: Option<Regex>,
}

impl CustomPattern {
    pub fn new(def: RuleDef) -> Result<Self, AppError> {
        let re = match &def.match_type {
            MatchType::Regex | MatchType::Keyword => {
                let expr = def.expression.as_deref().unwrap_or("");
                Some(
                    Regex::new(expr)
                        .map_err(|e| AppError::Config {
                            path: def.name.clone(),
                            reason: format!("invalid regex '{}': {}", expr, e),
                        })?,
                )
            }
            MatchType::Field => None,
        };
        Ok(Self { def, re })
    }

    fn check_field(&self, entry: &LogEntry) -> bool {
        let field_name = match self.def.field.as_deref() {
            Some(f) => f,
            None => return false,
        };
        let fv = match entry.fields.get(field_name) {
            Some(v) => v,
            None => return false,
        };

        let condition = self.def.condition.as_deref().unwrap_or("equals");
        let expected = match self.def.value.as_deref() {
            Some(v) => v,
            None => return false,
        };

        match condition {
            "equals" => match fv {
                FieldValue::String(s) => s == expected,
                FieldValue::Number(n) => expected.parse::<f64>().map_or(false, |v| (n - v).abs() < f64::EPSILON),
                FieldValue::Boolean(b) => expected == "true" && *b || expected == "false" && !*b,
                FieldValue::Null => false,
            },
            "contains" => match fv {
                FieldValue::String(s) => s.contains(expected),
                _ => false,
            },
            _ => false,
        }
    }
}

impl Pattern for CustomPattern {
    fn name(&self) -> &str {
        &self.def.name
    }
    fn description(&self) -> &str {
        &self.def.description
    }
    fn severity(&self) -> Severity {
        self.def.severity.clone()
    }
    fn check(&self, entry: &LogEntry) -> bool {
        match &self.def.match_type {
            MatchType::Regex => self
                .re
                .as_ref()
                .map_or(false, |r| r.is_match(&entry.message)),
            MatchType::Keyword => {
                let keyword = self.def.expression.as_deref().unwrap_or("");
                entry.message.to_lowercase().contains(&keyword.to_lowercase())
            }
            MatchType::Field => self.check_field(entry),
        }
    }
    fn min_count(&self) -> u64 {
        if self.def.count_threshold > 0 {
            self.def.count_threshold
        } else {
            1
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

pub fn load_rules(path: &Path) -> Result<Vec<Box<dyn Pattern>>, AppError> {
    let content = std::fs::read_to_string(path)?;
    let rule_file: CustomRule =
        toml::from_str(&content).map_err(|e| AppError::Config {
            path: path.display().to_string(),
            reason: format!("TOML parse error: {}", e),
        })?;

    let mut patterns: Vec<Box<dyn Pattern>> = Vec::new();
    for def in rule_file.rules {
        patterns.push(Box::new(CustomPattern::new(def)?));
    }
    Ok(patterns)
}
