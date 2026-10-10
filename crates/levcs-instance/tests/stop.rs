//! The instance binary stops gracefully: SIGTERM, which `systemctl stop`
//! sends, ends it with status 0 once what is in flight has finished. It
//! used to die at the signal, mid-push if one was running, leaving the
//! push for the next start to roll back.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn sigterm_stops_the_instance_cleanly() {
    let root = std::env::temp_dir().join(format!("levcs-stop-{}", std::process::id()));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_levcs-instance"))
        .arg("--root")
        .arg(&root)
        .args(["--bind", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let healthy = |port| -> bool {
        let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
            return false;
        };
        let _ = write!(
            s,
            "GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        );
        let mut text = String::new();
        let _ = s.read_to_string(&mut text);
        text.starts_with("HTTP/1.1 200")
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !healthy(port) {
        assert!(child.try_wait().unwrap().is_none(), "the instance exited");
        assert!(Instant::now() < deadline, "the instance never answered");
        std::thread::sleep(Duration::from_millis(50));
    }
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the instance did not stop within 30s of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut log = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert!(status.success(), "{status}: {log}");
    assert!(log.contains("stopping: no new requests"), "{log}");
    assert!(log.contains("stopped"), "{log}");
}
