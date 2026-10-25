// Synthetic process probe compiled only by launcher integration tests. Never
// included in release archives or registered as a product binary.
use std::{ffi::OsStr, io::{Read, Write}};

fn hex(value: &OsStr) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().map(|b| format!("{b:04x}")).collect()
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(windows)]
    if args.first().is_some_and(|arg| arg == "console-events") {
        use std::sync::atomic::{AtomicU32, Ordering};
        static EVENTS: AtomicU32 = AtomicU32::new(0);
        unsafe extern "system" fn on_event(event: u32) -> i32 {
            if event > 1 { return 0; }
            EVENTS.fetch_add(1, Ordering::SeqCst);
            1
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
        }
        // SAFETY: the callback is static and only updates an atomic.
        assert_ne!(unsafe { SetConsoleCtrlHandler(Some(on_event), 1) }, 0);
        println!("console-ready");
        std::io::stdout().flush().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut seen = 0;
        while std::time::Instant::now() < deadline {
            let count = EVENTS.load(Ordering::SeqCst);
            if count > seen {
                println!("handled-{count}");
                std::io::stdout().flush().unwrap();
                seen = count;
            }
            if count >= 2 {
                println!("cleanup-complete");
                std::io::stdout().flush().unwrap();
                std::process::exit(37);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        std::process::exit(98);
    }
    if args.first().is_some_and(|arg| arg == "write-marker") {
        std::fs::write(&args[1], b"started").unwrap();
        return;
    }
    if args.first().is_some_and(|arg| arg == "wait-for-termination") {
        std::thread::sleep(std::time::Duration::from_secs(20));
        std::process::exit(99);
    }
    if args.first().is_some_and(|arg| arg == "exit") {
        std::process::exit(args[1].to_str().unwrap().parse::<u32>().unwrap() as i32);
    }
    #[cfg(unix)]
    if args.first().is_some_and(|arg| arg == "signal") {
        unsafe extern "C" { fn kill(pid: i32, sig: i32) -> i32; fn getpid() -> i32; }
        // SAFETY: sends SIGTERM to this synthetic probe only.
        unsafe { kill(getpid(), 15); }
        panic!("signal did not terminate probe");
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut output = std::io::stdout().lock();
    writeln!(output, "pid={}", std::process::id()).unwrap();
    writeln!(output, "cwd={}", hex(std::env::current_dir().unwrap().canonicalize().unwrap().as_os_str())).unwrap();
    writeln!(output, "env={}", hex(&std::env::var_os("ASG_LAUNCHER_TEST_VALUE").unwrap_or_default())).unwrap();
    for arg in args { writeln!(output, "arg={}", hex(&arg)).unwrap(); }
    writeln!(output, "stdin={}", input.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap();
    std::io::stderr().write_all(b"synthetic-stderr\n").unwrap();
}
