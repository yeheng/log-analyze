pub mod generic;
pub mod json;
pub mod syslog;
pub mod nginx;
pub mod apache;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::core::error::AppError;
use crate::core::parser::LogParser;
use crate::core::types::DetectedFormat;

use self::apache::ApacheParser;
use self::generic::GenericParser;
use self::json::JsonParser;
use self::nginx::NginxParser;
use self::syslog::SyslogParser;

const SAMPLE_LINES: usize = 10;

pub struct Detector;

impl Detector {
    pub fn new() -> Self {
        Detector
    }

    pub fn detect(&self, path: &Path) -> Result<(DetectedFormat, Box<dyn LogParser>), AppError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let lines: Vec<Vec<u8>> = reader
            .lines()
            .take(SAMPLE_LINES)
            .filter_map(|l| l.ok())
            .map(|l| l.into_bytes())
            .collect();

        if lines.is_empty() {
            return Ok((
                DetectedFormat {
                    name: "empty".to_string(),
                    confidence: 1.0,
                },
                Box::new(GenericParser),
            ));
        }

        // Try JSON
        let json_score = Self::score_json(&lines);
        if json_score > 0.8 {
            return Ok((
                DetectedFormat {
                    name: "json".to_string(),
                    confidence: json_score,
                },
                Box::new(JsonParser),
            ));
        }

        // Try syslog
        let syslog_score = Self::score_syslog(&lines);
        if syslog_score > 0.8 {
            return Ok((
                DetectedFormat {
                    name: "syslog".to_string(),
                    confidence: syslog_score,
                },
                Box::new(SyslogParser),
            ));
        }

        // Score nginx and apache together — their combined formats are
        // structurally identical, so use filename as a tiebreaker.
        let nginx_score = Self::score_nginx(&lines);
        let apache_score = Self::score_apache(&lines);

        if nginx_score > 0.8 || apache_score > 0.8 {
            let (name, score, parser): (&str, f64, Box<dyn LogParser>) =
                if nginx_score > apache_score {
                    ("nginx", nginx_score, Box::new(NginxParser))
                } else if apache_score > nginx_score {
                    ("apache", apache_score, Box::new(ApacheParser))
                } else {
                    // Tied — use filename as hint
                    let filename = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    if filename.contains("nginx") {
                        ("nginx", nginx_score, Box::new(NginxParser))
                    } else {
                        ("apache", apache_score, Box::new(ApacheParser))
                    }
                };
            return Ok((
                DetectedFormat {
                    name: name.to_string(),
                    confidence: score,
                },
                parser,
            ));
        }

        // Pick the best scoring parser, or fall back to generic
        let candidates: Vec<(&str, f64, Box<dyn LogParser>)> = vec![
            ("json", json_score, Box::new(JsonParser)),
            ("syslog", syslog_score, Box::new(SyslogParser)),
            ("nginx", nginx_score, Box::new(NginxParser)),
            ("apache", apache_score, Box::new(ApacheParser)),
        ];

        let best = candidates.into_iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)).unwrap();

        if best.1 > 0.3 {
            Ok((
                DetectedFormat {
                    name: best.0.to_string(),
                    confidence: best.1,
                },
                best.2,
            ))
        } else {
            Ok((
                DetectedFormat {
                    name: "generic".to_string(),
                    confidence: 1.0,
                },
                Box::new(GenericParser),
            ))
        }
    }

    fn score_json(lines: &[Vec<u8>]) -> f64 {
        let parsed = lines
            .iter()
            .filter(|l| {
                let s = String::from_utf8_lossy(l).trim().to_string();
                serde_json::from_str::<serde_json::Value>(&s).is_ok()
            })
            .count();
        parsed as f64 / lines.len() as f64
    }

    fn score_syslog(lines: &[Vec<u8>]) -> f64 {
        let parser = SyslogParser;
        let parsed = lines
            .iter()
            .filter(|l| parser.parse(l, 0).is_some())
            .count();
        parsed as f64 / lines.len() as f64
    }

    fn score_nginx(lines: &[Vec<u8>]) -> f64 {
        let parser = NginxParser;
        let parsed = lines
            .iter()
            .filter(|l| parser.parse(l, 0).is_some())
            .count();
        parsed as f64 / lines.len() as f64
    }

    fn score_apache(lines: &[Vec<u8>]) -> f64 {
        let parser = ApacheParser;
        let parsed = lines
            .iter()
            .filter(|l| parser.parse(l, 0).is_some())
            .count();
        parsed as f64 / lines.len() as f64
    }
}
