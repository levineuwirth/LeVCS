//! Peer-to-peer transfer (§7.3.6): `deploy` sends, `dial` receives.
//!
//! `dial` is refused until it checks what it receives against the genesis
//! the repository's id pins (`doc/authority-semantics.md`, Rule R). It used
//! to install whatever a sender sent after the handshake, and nothing binds
//! those frames to the handshake (audit H3). The round trip it was tested
//! by is in this file's history, for when dial meets the rule.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(args: &[&str], cwd: &Path, xdg: &Path) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_levcs"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("run levcs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn tempdir(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("{prefix}-{n}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// `dial` is refused before it reads a key (the one it is given does not
/// exist), connects to the sender, or writes anything.
#[test]
fn dial_is_refused_before_it_does_anything() {
    let xdg = tempdir("levcs-p2p-xdg");
    let cwd = tempdir("levcs-p2p-recv");
    let sender = TcpListener::bind("127.0.0.1:0").unwrap();
    sender.set_nonblocking(true).unwrap();
    let addr = sender.local_addr().unwrap().to_string();
    let sender_key = format!("ed25519:{}", "11".repeat(32));
    let dest = cwd.join("dialed");
    let (code, _, e) = run(
        &[
            "dial",
            &addr,
            &sender_key,
            "--key",
            "nobody",
            dest.to_str().unwrap(),
        ],
        &cwd,
        &xdg,
    );
    assert_ne!(code, 0, "dial ran");
    assert!(
        e.contains("dial is refused until it checks what it receives"),
        "{e}"
    );
    assert!(!dest.exists(), "dial wrote {}", dest.display());
    assert!(
        matches!(sender.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "dial connected to the sender"
    );
    let _ = std::fs::remove_dir_all(&cwd);
    let _ = std::fs::remove_dir_all(&xdg);
}
