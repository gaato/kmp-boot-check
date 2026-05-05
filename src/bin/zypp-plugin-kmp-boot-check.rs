use std::io::{self, Read, Write};
use std::process::Command;

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    for frame in input.split(|byte| *byte == 0) {
        if frame.is_empty() {
            continue;
        }
        let command = frame
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .unwrap_or("");
        match command {
            "PLUGINBEGIN" => ack()?,
            "PACKAGESETCHANGED" => {
                run_check();
                ack()?;
            }
            "PLUGINEND" | "_DISCONNECT" => {
                ack()?;
                break;
            }
            _ => enomethod()?,
        }
    }
    Ok(())
}

fn run_check() {
    let checker = std::env::var("KMP_BOOT_CHECK_BIN")
        .unwrap_or_else(|_| "/usr/bin/kmp-boot-check".to_string());
    let output = Command::new(checker).arg("--strict").output();

    let Ok(output) = output else {
        eprintln!("kmp-boot-check is not available; skipping KMP boot check.");
        return;
    };

    if !output.stdout.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    if !output.status.success() {
        eprintln!("kmp-boot-check reported a possible boot risk after package changes.");
    }
}

fn ack() -> io::Result<()> {
    io::stdout().write_all(b"ACK\n\n\0")
}

fn enomethod() -> io::Result<()> {
    io::stdout().write_all(b"_ENOMETHOD\n\n\0")
}
