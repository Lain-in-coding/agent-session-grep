use std::io::Write;

fn main() {
    // An unexpected panic must obey the same content-free failure boundary.
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        agent_session_grep_launcher::run(&args, &mut std::io::stdout())
    })
    .unwrap_or(Err(agent_session_grep_launcher::LauncherError::Internal));
    let status = match result {
        Ok(status) => status,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "{error}");
            error.exit_code()
        }
    };
    std::process::exit(status);
}
