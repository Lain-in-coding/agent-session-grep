//! Consistency smoke test: shells the five-entry-point comparison script
//! (``scripts/rehearsal/compare_entrypoints.py``) in fixtures-only mode against
//! the freshly compiled binary. The Web adapter launches the real loopback
//! server; TUI is checked through its headless structural projection.
//! No real transcripts or terminal automation are involved.

use std::path::PathBuf;
use std::process::{Command, Output};

/// The compiled binary path injected by Cargo at build time.
const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");

/// Repo root: two levels up from this test's crate directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir must have a parent")
        .parent()
        .expect("workspace dir must have a parent")
        .to_path_buf()
}

fn consistency_script() -> PathBuf {
    repo_root()
        .join("scripts")
        .join("rehearsal")
        .join("compare_entrypoints.py")
}

fn run_script(args: &[&str]) -> Output {
    // Prefer `python` (Windows), fall back to `python3` (POSIX). Once an
    // interpreter successfully spawns, preserve its real exit/output instead
    // of allowing a later WindowsApps launcher stub to mask the failure.
    for interpreter in ["python", "python3"] {
        if let Ok(output) = Command::new(interpreter)
            .arg(consistency_script())
            .args(args)
            .output()
        {
            return output;
        }
    }
    panic!("failed to spawn python for compare_entrypoints.py")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn consistency_report_all_five_entry_points_agree() {
    let script = consistency_script();
    assert!(
        script.is_file(),
        "consistency script must exist: {}",
        script.display()
    );

    let out = run_script(&["--binary", BIN, "--json"]);
    let code = out.status.code().unwrap_or(-1);
    let stderr_text = stderr(&out);
    assert!(
        out.status.success(),
        "compare_entrypoints.py must exit 0, got {code}\nstderr: {stderr_text}"
    );

    let report: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("report must be valid JSON");

    // Schema version must match.
    assert_eq!(
        report["schema_version"].as_str().unwrap_or(""),
        "agent-session-grep.entrypoint-consistency/v1",
        "report schema_version mismatch"
    );

    // Overall verdict must be consistent.
    assert_eq!(
        report["overall_verdict"].as_str().unwrap_or(""),
        "consistent",
        "overall_verdict must be consistent, got: {}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );

    // Every operation must be consistent and every entry point directly
    // compared. Release consistency no longer permits skipped or
    // alias-as-pass surfaces.
    let operations = report["operations"]
        .as_array()
        .expect("report.operations must be an array");
    assert!(
        !operations.is_empty(),
        "report must have at least one operation"
    );
    for op in operations {
        assert_eq!(
            op["verdict"].as_str().unwrap_or(""),
            "consistent",
            "operation {} must be consistent",
            op["operation"]
        );
        let compared: Vec<&str> = op["compared"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert_eq!(compared, vec!["cli", "mcp", "robot", "web", "tui"]);
        assert!(
            op["skipped"].as_array().is_some_and(Vec::is_empty),
            "no entry point may be skipped"
        );
        assert!(
            op["aliases"].as_array().is_some_and(Vec::is_empty),
            "Robot must be exercised, not assumed as an alias"
        );
        assert!(
            op["unimplemented"].as_array().is_some_and(Vec::is_empty),
            "an unimplemented entry point must fail the harness"
        );
    }

    // Entry-point metadata must declare and implement all five.
    let declared: Vec<&str> = report["entry_points"]["declared"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    assert_eq!(declared, vec!["cli", "mcp", "robot", "web", "tui"]);
    let implemented: Vec<&str> = report["entry_points"]["implemented"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    assert_eq!(implemented, declared);
    assert!(
        report["entry_points"]["pending"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    // Privacy fields must be asserted in the report.
    let privacy = &report["privacy"];
    assert_eq!(
        privacy["message_text"].as_str().unwrap_or(""),
        "never_compared"
    );
    assert_eq!(
        privacy["absolute_source_paths"].as_str().unwrap_or(""),
        "never_emitted"
    );
}

#[test]
fn consistency_script_help_runs() {
    let out = run_script(&["--help"]);
    assert!(
        out.status.success(),
        "--help must exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("--binary"),
        "--help must mention --binary, got: {text}"
    );
}
