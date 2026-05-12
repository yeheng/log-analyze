use std::path::PathBuf;

use log_analyze::parsers::Detector;

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    path
}

#[test]
fn detect_identifies_json_format() {
    let detector = Detector::new();
    let path = fixture_path("json.log");
    let (format, parser) = detector.detect(&path).unwrap();
    assert_eq!(format.name, "json");
    assert_eq!(parser.name(), "json");
}

#[test]
fn detect_identifies_syslog_format() {
    let detector = Detector::new();
    let path = fixture_path("syslog.log");
    let (format, parser) = detector.detect(&path).unwrap();
    assert_eq!(format.name, "syslog");
    assert_eq!(parser.name(), "syslog");
}

#[test]
fn detect_identifies_nginx_format() {
    let detector = Detector::new();
    let path = fixture_path("nginx.log");
    let (format, parser) = detector.detect(&path).unwrap();
    assert_eq!(format.name, "nginx");
    assert_eq!(parser.name(), "nginx");
}

#[test]
fn detect_identifies_apache_format() {
    let detector = Detector::new();
    let path = fixture_path("apache.log");
    let (format, parser) = detector.detect(&path).unwrap();
    assert_eq!(format.name, "apache");
    assert_eq!(parser.name(), "apache");
}

#[test]
fn detect_identifies_apache_combined_format() {
    let detector = Detector::new();
    let path = fixture_path("apache_combined.log");
    let (format, parser) = detector.detect(&path).unwrap();
    assert_eq!(format.name, "apache");
    assert_eq!(parser.name(), "apache");
}

#[test]
fn detect_returns_error_for_missing_file() {
    let detector = Detector::new();
    let result = detector.detect(PathBuf::from("/nonexistent/file.log").as_path());
    assert!(result.is_err());
}
