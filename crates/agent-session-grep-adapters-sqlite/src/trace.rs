//! Temporary, env-gated index-throughput stage timing.
//!
//! Inert unless `ASG_INDEX_TRACE` names a file to append to: default product
//! runs pay one `OnceLock` read and never touch the file system. Measurement
//! scaffolding for local indexing diagnostics; disabled unless explicitly enabled.
#![allow(dead_code)]

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static TARGET: OnceLock<Option<PathBuf>> = OnceLock::new();
static ORIGIN: OnceLock<Instant> = OnceLock::new();

fn target() -> Option<&'static PathBuf> {
    TARGET
        .get_or_init(|| std::env::var_os("ASG_INDEX_TRACE").map(PathBuf::from))
        .as_ref()
}

pub(crate) fn enabled() -> bool {
    target().is_some()
}

pub(crate) fn begin() -> Option<Instant> {
    target().map(|_| Instant::now())
}

pub(crate) fn elapsed(started: Option<Instant>) -> Duration {
    started.map_or(Duration::ZERO, |started| started.elapsed())
}

pub(crate) fn add(
    stages: &mut Vec<(&'static str, Duration)>,
    stage: &'static str,
    started: Option<Instant>,
) {
    if let Some(started) = started {
        stages.push((stage, started.elapsed()));
    }
}

pub(crate) fn emit(label: &str, stages: &[(&'static str, Duration)], detail: &str) {
    let Some(path) = target() else {
        return;
    };
    let mut stage_map = serde_json::Map::new();
    for (stage, duration) in stages {
        let ms = duration.as_secs_f64() * 1000.0;
        let rounded = (ms * 1000.0).round() / 1000.0;
        stage_map.insert((*stage).to_string(), serde_json::json!(rounded));
    }
    let origin = ORIGIN.get_or_init(Instant::now);
    let record = serde_json::json!({
        "schema": "asg.index-trace/v1",
        "pid": std::process::id(),
        "t_ms": (origin.elapsed().as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0,
        "label": label,
        "stages_ms": serde_json::Value::Object(stage_map),
        "detail": detail,
    });
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{record}");
    }
}
