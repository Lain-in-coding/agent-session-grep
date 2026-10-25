//! Test-only forwarding launcher; not native launcher acceptance evidence.
fn main() {
    let executable = std::env::current_exe().unwrap();
    let app = executable
        .parent()
        .unwrap()
        .join(env!("ASG_TEST_APP_RELATIVE"));
    let status = std::process::Command::new(app)
        .args(std::env::args_os().skip(1))
        .status()
        .unwrap();
    std::process::exit(status.code().unwrap_or(1));
}
