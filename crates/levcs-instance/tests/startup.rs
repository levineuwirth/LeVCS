//! What the instance binary writes as it starts.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const INSTANCE: &str = env!("CARGO_BIN_EXE_levcs-instance");

/// An instance started with its log piped, as under systemd, stopped and
/// its root removed when dropped.
struct Started {
    child: Child,
    root: PathBuf,
    /// What it logged up to and including the line that says it is starting.
    log: Vec<String>,
}

impl Started {
    fn new(tag: &str) -> Started {
        let root = std::env::temp_dir().join(format!("levcs-{tag}-{}", std::process::id()));
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(INSTANCE)
            .arg("--root")
            .arg(&root)
            .args(["--bind", &format!("127.0.0.1:{port}")])
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut started = Started {
            child,
            root,
            log: Vec::new(),
        };
        let (send, lines) = mpsc::channel();
        let stdout = started.child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if send.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no startup line in 30s; before it: {:?}", started.log));
            let last = line.contains("levcs instance starting");
            started.log.push(line);
            if last {
                return started;
            }
        }
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Under systemd the log goes to the journal, which kept the colour codes
/// the instance used to write as escapes in every line.
#[test]
fn a_log_that_is_not_a_terminal_has_no_colour() {
    let started = Started::new("startup-colour");
    for line in &started.log {
        assert!(!line.contains('\x1b'), "an escape code in {line:?}");
    }
}
