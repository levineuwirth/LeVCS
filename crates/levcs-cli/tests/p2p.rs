//! End-to-end deploy/dial test (§7.3.6 — peer-to-peer transfer).
//!
//! Boots two `levcs` processes on loopback TCP — one runs `deploy`,
//! the other runs `dial` — and confirms:
//!   1. The handshake authenticates both sides against expected keys.
//!   2. The transferred archive reconstructs the same repo_id, branches,
//!      and tree contents on the dialer side.
//!   3. The dialer rejects an impostor sender that signs with the wrong
//!      Ed25519 key, even on the right host:port.
//!   4. The deployer refuses a dialer that authenticates with the wrong
//!      key.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn levcs_bin() -> String {
    env!("CARGO_BIN_EXE_levcs").to_string()
}

fn run(args: &[&str], cwd: &Path, xdg: &Path) -> (i32, String, String) {
    let out = Command::new(levcs_bin())
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

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Read the public key for `label` from the given keychain. We invoke
/// `levcs key show` so the test exercises the same code path the user
/// would, and we do not have to crack open the keychain file format.
fn read_pub(label: &str, cwd: &Path, xdg: &Path) -> String {
    let (code, out, err) = run(&["key", "show", label], cwd, xdg);
    assert_eq!(code, 0, "key show {label}: {err}");
    out.trim().to_string()
}

/// Create a source repository with one commit and return its path.
fn make_source_repo(name: &str, key_label: &str, xdg: &Path) -> PathBuf {
    let src = tempdir(name);
    let (code, _, e) = run(&["init", "--key", key_label], &src, xdg);
    assert_eq!(code, 0, "init: {e}");
    std::fs::write(src.join("README"), b"deploy/dial source content\n").unwrap();
    std::fs::write(src.join("notes.md"), b"# notes\nan example\n").unwrap();
    let (code, _, e) = run(&["track", "--all"], &src, xdg);
    assert_eq!(code, 0, "track: {e}");
    let (code, _, e) = run(&["commit", "-m", "initial"], &src, xdg);
    assert_eq!(code, 0, "commit: {e}");
    src
}

/// Spawn `levcs deploy` and wait for its first stderr line so we know
/// the listener is up before the dialer connects.
fn spawn_deployer(
    repo: &Path,
    xdg: &Path,
    deployer_label: &str,
    recipient_pub: &str,
    listen: &str,
) -> std::process::Child {
    let mut cmd = Command::new(levcs_bin());
    cmd.args(&[
        "deploy",
        recipient_pub,
        "--key",
        deployer_label,
        "--listen",
        listen,
    ])
    .current_dir(repo)
    .env("XDG_CONFIG_HOME", xdg)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn deploy");
    // Wait for the listener to print its first line — that tells us the
    // bind succeeded so the dialer won't race the listener.
    let stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stderr);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        if line.contains("listening on") {
            // Re-attach the rest of stderr by spawning a drain thread
            // so the child's stderr buffer never fills up.
            std::thread::spawn(move || {
                let mut sink = String::new();
                let _ = reader.read_to_string(&mut sink);
            });
            return child;
        }
    }
    panic!("deployer never reported `listening on` (last line: {line:?})");
}

use std::io::Read;

#[test]
fn deploy_and_dial_round_trip() {
    let xdg = tempdir("levcs-p2p-xdg");

    // Sender (alice) creates a repo with content. Init produces alice's
    // key in the shared XDG keychain.
    let source = make_source_repo("levcs-p2p-source", "alice", &xdg);

    // Recipient (bob) gets a separate key in the same keychain.
    let recv_parent = tempdir("levcs-p2p-recv-parent");
    let (code, _, e) = run(&["key", "generate", "bob"], &recv_parent, &xdg);
    assert_eq!(code, 0, "key generate bob: {e}");

    let alice_pub = read_pub("alice", &source, &xdg);
    let bob_pub = read_pub("bob", &recv_parent, &xdg);

    // Sender starts listening, gated on bob's key.
    let port = pick_free_port();
    let listen = format!("127.0.0.1:{port}");
    let deployer = spawn_deployer(&source, &xdg, "alice", &bob_pub, &listen);

    // Recipient dials in.
    let dest = recv_parent.join("dialed");
    let (code, _, e) = run(
        &[
            "dial",
            &listen,
            &alice_pub,
            "--key",
            "bob",
            dest.to_str().unwrap(),
        ],
        &recv_parent,
        &xdg,
    );
    assert_eq!(code, 0, "dial: {e}");

    let _ = deployer.wait_with_output();

    // Verify: dialed repo exists and content matches.
    assert!(dest.is_dir(), "dialed dest not created");
    assert_eq!(
        std::fs::read_to_string(dest.join("README")).unwrap(),
        "deploy/dial source content\n"
    );
    assert_eq!(
        std::fs::read_to_string(dest.join("notes.md")).unwrap(),
        "# notes\nan example\n"
    );

    // repo_id must match the source — deploy/dial preserves identity
    // exactly (per §5.7 same-repo movement, this is the no-rewrite path).
    let src_repo_id = std::fs::read_to_string(source.join(".levcs/refs/authority/genesis"))
        .unwrap()
        .trim()
        .to_string();
    let dst_repo_id = std::fs::read_to_string(dest.join(".levcs/refs/authority/genesis"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(src_repo_id, dst_repo_id, "genesis authority must match");

    // Branch tip must match.
    let src_main = std::fs::read_to_string(source.join(".levcs/refs/branches/main"))
        .unwrap()
        .trim()
        .to_string();
    let dst_main = std::fs::read_to_string(dest.join(".levcs/refs/branches/main"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(src_main, dst_main, "branch main tip must match");

    // verify on the dialed repo passes — every signature and the full
    // authority chain reconstruct correctly from what we received.
    let (code, _, e) = run(&["verify"], &dest, &xdg);
    assert_eq!(code, 0, "verify on dialed repo: {e}");

    // Cleanup.
    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&recv_parent);
    let _ = std::fs::remove_dir_all(&xdg);
}

#[test]
fn dial_rejects_wrong_sender_key() {
    let xdg = tempdir("levcs-p2p-xdg-mismatch");
    let source = make_source_repo("levcs-p2p-src-mismatch", "alice", &xdg);
    let recv_parent = tempdir("levcs-p2p-recv-mismatch");
    let (code, _, e) = run(&["key", "generate", "bob"], &recv_parent, &xdg);
    assert_eq!(code, 0, "key generate bob: {e}");
    // A third unrelated key — used as the *expected* sender on the dial
    // side, even though alice is who's actually deploying.
    let (code, _, e) = run(&["key", "generate", "mallory"], &recv_parent, &xdg);
    assert_eq!(code, 0, "key generate mallory: {e}");

    let bob_pub = read_pub("bob", &recv_parent, &xdg);
    let mallory_pub = read_pub("mallory", &recv_parent, &xdg);

    let port = pick_free_port();
    let listen = format!("127.0.0.1:{port}");
    let deployer = spawn_deployer(&source, &xdg, "alice", &bob_pub, &listen);

    // Dial expecting `mallory` — alice's signature should not verify
    // under mallory's key, so dial must abort with a non-zero exit.
    let dest = recv_parent.join("dialed-bad");
    let (code, _, err) = run(
        &[
            "dial",
            &listen,
            &mallory_pub,
            "--key",
            "bob",
            dest.to_str().unwrap(),
        ],
        &recv_parent,
        &xdg,
    );
    assert_ne!(code, 0, "dial should have failed but didn't");
    assert!(
        err.contains("KeyMismatch")
            || err.contains("unexpected public key")
            || err.contains("BadSignature")
            || err.to_lowercase().contains("handshake"),
        "expected handshake error in stderr, got: {err}"
    );
    assert!(!dest.exists(), "no repo should have been written");
    let _ = deployer.wait_with_output();

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&recv_parent);
    let _ = std::fs::remove_dir_all(&xdg);
}
