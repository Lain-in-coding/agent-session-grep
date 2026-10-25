#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    std::process::exit(agent_session_grep_cli::managed_supervisor::run_entry(&args));
}
