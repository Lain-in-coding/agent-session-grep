//! Canonical `agent-session-grep` command entry point.
//!
//! The whole CLI lives in the crate library so the two installed command names
//! share one compilation unit and one test run; this shim only forwards to it.
//! Before the split, both bin targets pointed at the same `main.rs`, which made
//! cargo compile the CLI twice and run its unit tests twice.

fn main() {
    agent_session_grep_cli::run_cli();
}
