//! `asg` alias command entry point.
//!
//! Same binary behaviour as `agent-session-grep`; the alias exists so the short
//! name works when a user installs from source. Both shims call the single
//! library entry point, so the CLI compiles and tests once.

fn main() {
    agent_session_grep_cli::run_cli();
}
