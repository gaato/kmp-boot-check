use std::io::{self, BufRead, Write};
use std::process::Command;

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut frame = Vec::new();

    while input.read_until(0, &mut frame)? != 0 {
        if frame.last() == Some(&0) {
            frame.pop();
        }
        if frame.is_empty() {
            frame.clear();
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
        frame.clear();
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
    write_response(b"ACK\n\n\0")
}

fn enomethod() -> io::Result<()> {
    write_response(b"_ENOMETHOD\n\n\0")
}

fn write_response(response: &[u8]) -> io::Result<()> {
    let mut stdout = io::stdout();
    stdout.write_all(response)?;
    stdout.flush()
}
