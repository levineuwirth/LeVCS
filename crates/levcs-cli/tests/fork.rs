//! End-to-end fork test:
//!   1. Spin up an in-process levcs instance.
//!   2. Run the levcs binary to init a source repo, commit, point at the
//!      instance, and push.
//!   3. Run the levcs binary in a fresh directory to fork the source.
//!   4. Run `levcs verify` in the fork to confirm the fork commit and chain.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use levcs_instance::{router, AppState, InstanceConfig};

fn levcs_bin() -> String {
    env!("CARGO_BIN_EXE_levcs").to_string()
}

fn run(args: &[&str], cwd: &Path, xdg: &Path, extra: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(levcs_bin());
    cmd.args(args).current_dir(cwd).env("XDG_CONFIG_HOME", xdg);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run levcs");
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

/// Spin up an axum instance bound to an ephemeral port. Returns (addr,
/// shutdown_handle).
async fn start_instance(root: PathBuf) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg = InstanceConfig {
        root,
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: vec!["builtin".into()],
        mirrors: Vec::new(),
    };
    let state = AppState::new(cfg);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, task)
}

#[test]
fn fork_end_to_end() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // 1. Boot an instance.
    let instance_root = tempdir("levcs-fork-instance");
    let instance_root_for_task = instance_root.clone();
    let (addr, server_task) =
        runtime.block_on(async move { start_instance(instance_root_for_task).await });
    let base_url = format!("http://{addr}/levcs/v1");

    // 2. Source repo.
    let source = tempdir("levcs-fork-source");
    let xdg = tempdir("levcs-fork-cfg");

    let (code, _, e) = run(&["init", "--key", "alice"], &source, &xdg, &[]);
    assert_eq!(code, 0, "init: {e}");
    std::fs::write(source.join("README"), b"source repo content\n").unwrap();
    let (code, _, e) = run(&["track", "--all"], &source, &xdg, &[]);
    assert_eq!(code, 0, "track: {e}");
    let (code, _, e) = run(&["commit", "-m", "initial"], &source, &xdg, &[]);
    assert_eq!(code, 0, "commit: {e}");

    // Point at the instance and push.
    let (code, _, e) = run(&["instance", "--set", &base_url], &source, &xdg, &[]);
    assert_eq!(code, 0, "instance --set: {e}");
    let (code, _, e) = run(&["push"], &source, &xdg, &[]);
    assert_eq!(code, 0, "push: {e}");

    // Look up the source's repo_id.
    let (code, repo_id_out, _) = run(&["root"], &source, &xdg, &[]);
    assert_eq!(code, 0);
    let _ = repo_id_out;
    // Easier: read genesis authority's repo_id from .levcs.
    let genesis_hex = std::fs::read_to_string(source.join(".levcs/refs/authority/genesis"))
        .unwrap()
        .trim()
        .to_string();
    // Now read the genesis object from the instance via the running server.
    // Or simpler: derive repo_id from the source repo by parsing its genesis.
    let genesis_path = source
        .join(".levcs/objects")
        .join(&genesis_hex[..2])
        .join(&genesis_hex[2..]);
    let bytes = std::fs::read(&genesis_path).unwrap();
    let signed = levcs_core::object::SignedObject::parse(&bytes).unwrap();
    let body = levcs_identity::authority::AuthorityBody::parse(&signed.body).unwrap();
    let repo_id_hex = body.repo_id.to_hex();

    // 3. Fork into a new directory using a different key (bob).
    let fork_parent = tempdir("levcs-fork-dest-parent");
    // Generate bob in the same xdg keychain so load_secret can find him.
    let (code, _, e) = run(&["key", "generate", "bob"], &fork_parent, &xdg, &[]);
    assert_eq!(code, 0, "key generate bob: {e}");
    let (code, _, e) = run(&["instance", "--set", &base_url], &fork_parent, &xdg, &[]);
    assert_eq!(code, 0, "instance --set (fork): {e}");

    let (code, _o, err) = run(
        &["fork", &repo_id_hex, "--name", "myfork", "--key", "bob"],
        &fork_parent,
        &xdg,
        &[],
    );
    assert_eq!(code, 0, "fork: {err}");

    // 4. Verify the fork.
    let fork_dir = fork_parent.join("myfork");
    assert!(fork_dir.is_dir(), "fork directory not created");
    assert!(
        fork_dir.join("README").is_file(),
        "source content not checked out"
    );
    assert_eq!(
        std::fs::read_to_string(fork_dir.join("README")).unwrap(),
        "source repo content\n"
    );

    let (code, _, e) = run(&["verify"], &fork_dir, &xdg, &[]);
    assert_eq!(code, 0, "verify of fork: {e}");

    // 5. Confirm the fork's repo_id differs from the source's.
    let fork_genesis_hex = std::fs::read_to_string(fork_dir.join(".levcs/refs/authority/genesis"))
        .unwrap()
        .trim()
        .to_string();
    let fork_genesis_path = fork_dir
        .join(".levcs/objects")
        .join(&fork_genesis_hex[..2])
        .join(&fork_genesis_hex[2..]);
    let fork_bytes = std::fs::read(&fork_genesis_path).unwrap();
    let fork_signed = levcs_core::object::SignedObject::parse(&fork_bytes).unwrap();
    let fork_body = levcs_identity::authority::AuthorityBody::parse(&fork_signed.body).unwrap();
    assert_ne!(
        fork_body.repo_id, body.repo_id,
        "fork repo_id must differ from source"
    );
    // Bob is the sole owner of the new genesis.
    assert_eq!(fork_body.members.len(), 1);
    assert_eq!(
        fork_body.members[0].role,
        levcs_identity::authority::Role::Owner
    );

    // 6. Confirm the fork commit has both flags set and a single parent.
    let head_hex = std::fs::read_to_string(fork_dir.join(".levcs/refs/branches/main"))
        .unwrap()
        .trim()
        .to_string();
    let head_id = levcs_core::ObjectId::from_hex(&head_hex).unwrap();
    let head_path = fork_dir
        .join(".levcs/objects")
        .join(&head_hex[..2])
        .join(&head_hex[2..]);
    let head_bytes = std::fs::read(&head_path).unwrap();
    let head_signed = levcs_core::object::SignedObject::parse(&head_bytes).unwrap();
    let head_commit = levcs_core::Commit::from_signed(&head_signed).unwrap();
    assert!(
        head_commit.flags.is_fork(),
        "fork commit must have fork flag set"
    );
    assert!(
        head_commit.flags.modifies_authority(),
        "fork commit must have modifies-authority flag set"
    );
    assert_eq!(head_commit.parents.len(), 1);
    let _ = head_id;

    // Done. Tear down.
    server_task.abort();
    runtime.shutdown_background();
    let _ = Arc::new(()); // keep tokio import live
    let _ = std::fs::remove_dir_all(instance_root);
    let _ = std::fs::remove_dir_all(source);
    let _ = std::fs::remove_dir_all(fork_parent);
    let _ = std::fs::remove_dir_all(xdg);
}
