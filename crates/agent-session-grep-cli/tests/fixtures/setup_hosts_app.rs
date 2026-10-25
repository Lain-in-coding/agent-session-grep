//! Synthetic local ASG protocol fixture. Never packaged or used as host evidence.
use std::{
    io::{Read, Write},
    time::Duration,
};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let binary = std::env::current_exe().unwrap();
    let mode = std::fs::read_to_string(binary.with_extension("mode")).unwrap_or_default();
    if args.first().is_some_and(|a| a == "descendant") {
        std::thread::sleep(Duration::from_secs(2));
        std::fs::write(
            binary.with_extension("escaped"),
            "unexpected live descendant",
        )
        .unwrap();
        return;
    }
    if mode == "tree" {
        // Intentionally retains inherited pipe handles after parent exits.
        let _child = std::process::Command::new(&binary)
            .arg("descendant")
            .spawn()
            .unwrap();
        return;
    }
    if mode == "hang" {
        std::thread::sleep(Duration::from_secs(60));
    }
    if mode == "flood" {
        let block = [b'x'; 4096];
        loop {
            if std::io::stdout().write_all(&block).is_err() {
                return;
            }
        }
    }
    if mode == "stderr" {
        eprintln!("synthetic-private-marker");
    }
    if args.first().is_some_and(|a| a == "capture-fixture") {
        println!("synthetic local manager output");
        if mode == "failure" {
            std::process::exit(17);
        }
        return;
    }
    if args.first().is_some_and(|a| a == "--version") {
        println!(
            "agent-session-grep {}",
            if mode == "wrong-version" {
                "9.0.0"
            } else {
                "0.1.0-fixture"
            }
        );
        return;
    }
    assert_eq!(args.len(), 3);
    assert_eq!(args[0], "--db");
    assert_eq!(args[2], "mcp");
    assert!(std::path::Path::new(&args[1]).is_file());
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    assert_eq!(input.lines().count(), 1);
    assert!(input.contains("\"method\":\"initialize\""));
    assert!(!input.contains("tools/call"));
    if mode == "bad-mcp" {
        println!("{{\"error\":\"synthetic-private-marker\"}}");
        return;
    }
    println!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2025-06-18","serverInfo":{{"name":"agent-session-grep","version":"0.1.0-fixture"}},"capabilities":{{"tools":{{}}}}}}}}"#
    );
}
