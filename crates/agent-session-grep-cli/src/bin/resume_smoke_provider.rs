//! Test-only fake provider binary for the resume smoke e2e test.
//!
//! The e2e test copies this binary to a temp dir named `claude` (or
//! `claude.exe` on Windows), puts that dir on PATH, and runs
//! `resume <ses-id> --yes`. When spawned, this provider records its current
//! working directory and argv to the paths given via env vars, then exits 0.
//! It is never shipped to users and does nothing outside the test harness.

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let (Ok(path), Ok(cwd)) = (
        std::env::var("RESUME_SMOKE_CWD_OUT"),
        std::env::current_dir(),
    ) && let Ok(mut file) = std::fs::File::create(&path)
    {
        let _ = file.write_all(cwd.to_string_lossy().as_bytes());
    }
    if let Ok(path) = std::env::var("RESUME_SMOKE_ARGS_OUT")
        && let Ok(mut file) = std::fs::File::create(&path)
    {
        let _ = file.write_all(args.join(" ").as_bytes());
    }
}
