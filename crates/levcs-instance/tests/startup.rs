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
    port: u16,
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
            port,
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

    fn starting(&self) -> &str {
        self.log.last().unwrap()
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

#[test]
fn version_names_the_commit() {
    for flag in ["--version", "-V"] {
        let out = Command::new(INSTANCE).arg(flag).output().unwrap();
        assert!(out.status.success(), "{flag}: {out:?}");
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            format!("levcs-instance {}\n", env!("LEVCS_VERSION")),
            "{flag}"
        );
    }
}

/// A running instance says which build it is: in the line it logs as it
/// starts, and in its info.
#[test]
fn the_running_instance_names_its_commit() {
    let started = Started::new("startup-commit");
    let commit = env!("LEVCS_BUILD_COMMIT");
    let line = started.starting();
    assert!(line.contains(commit), "{line:?} does not name {commit}");
    assert!(
        line.contains(env!("CARGO_PKG_VERSION")),
        "{line:?} does not name the version"
    );

    let client = levcs_client::Client::new(format!("http://127.0.0.1:{}/levcs/v1", started.port));
    let deadline = Instant::now() + Duration::from_secs(30);
    let info = loop {
        match client.instance_info() {
            Ok(info) => break info,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("the instance never answered: {e}"),
        }
    };
    assert_eq!(info.commit.as_deref(), Some(commit));
}
