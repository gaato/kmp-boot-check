use std::fs;
use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn zypp_plugin_acknowledges_successful_checker_run() {
    let checker = fake_checker("checker ok", 0);
    let output = run_plugin(
        b"PLUGINBEGIN\n\n\0PACKAGESETCHANGED\n\n\0PLUGINEND\n\n\0",
        &checker,
    );

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "ACK\n\n\0ACK\n\n\0ACK\n\n\0"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("checker ok --strict"));
}

#[test]
fn zypp_plugin_acknowledges_pluginbegin_before_stdin_closes() {
    let checker = fake_checker("not used yet", 0);
    let plugin = std::env::var("CARGO_BIN_EXE_zypp-plugin-kmp-boot-check")
        .expect("plugin binary path should be provided by cargo test");
    let mut child = Command::new(plugin)
        .env("KMP_BOOT_CHECK_BIN", checker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin");

    let mut stdin = child.stdin.take().expect("plugin stdin");
    let mut stdout = child.stdout.take().expect("plugin stdout");
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let mut response = [0_u8; 6];
        let result = stdout.read_exact(&mut response).map(|_| response);
        let _ = tx.send(result);
        let mut remaining = Vec::new();
        let _ = stdout.read_to_end(&mut remaining);
    });

    stdin
        .write_all(b"PLUGINBEGIN\n\n\0")
        .expect("write pluginbegin");
    let response = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("pluginbegin ack should be written before stdin closes")
        .expect("read pluginbegin ack");
    assert_eq!(&response, b"ACK\n\n\0");

    stdin
        .write_all(b"_DISCONNECT\n\n\0")
        .expect("write disconnect");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for plugin");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());
}

#[test]
fn zypp_plugin_reports_failed_checker_run_without_blocking_protocol() {
    let checker = fake_checker("checker risk", 2);
    let output = run_plugin(
        b"PLUGINBEGIN\n\n\0PACKAGESETCHANGED\n\n\0PLUGINEND\n\n\0",
        &checker,
    );

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "ACK\n\n\0ACK\n\n\0ACK\n\n\0"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("checker risk --strict"));
    assert!(stderr.contains("kmp-boot-check reported a possible boot risk"));
}

#[test]
fn zypp_plugin_rejects_unknown_commands() {
    let checker = fake_checker("not used", 0);
    let output = run_plugin(b"UNKNOWN\n\n\0_DISCONNECT\n\n\0", &checker);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "_ENOMETHOD\n\n\0ACK\n\n\0"
    );
    assert!(output.stderr.is_empty());
}

fn run_plugin(input: &[u8], checker: &std::path::Path) -> std::process::Output {
    let plugin = std::env::var("CARGO_BIN_EXE_zypp-plugin-kmp-boot-check")
        .expect("plugin binary path should be provided by cargo test");
    let mut child = Command::new(plugin)
        .env("KMP_BOOT_CHECK_BIN", checker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin");
    child
        .stdin
        .as_mut()
        .expect("plugin stdin")
        .write_all(input)
        .expect("write plugin input");
    child.wait_with_output().expect("wait for plugin")
}

fn fake_checker(message: &str, exit_code: i32) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kmp-boot-check-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("checker");
    fs::write(
        &path,
        format!("#!/bin/sh\necho \"{message} $*\" >&2\nexit {exit_code}\n"),
    )
    .expect("write fake checker");

    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&path)
            .expect("stat fake checker")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("chmod fake checker");
    }

    path
}
