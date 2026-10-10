//! End-to-end test for `levcs inspect`.
//!
//! Boots an in-process instance, pushes a repo with a small tree, then
//! drives the `levcs inspect` binary against it. Verifies the output
//! lists the current authority, branch heads, and the requested tree
//! contents (§7.3.5).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use levcs_instance::{router, AppState, InstanceConfig};

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

async fn start_instance(
    root: PathBuf,
    creators: Vec<String>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg = InstanceConfig {
        root,
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
        creators,
        limits: Default::default(),
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
fn inspect_lists_branches_authority_and_tree() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let source = tempdir("levcs-inspect-src");
    let xdg = tempdir("levcs-inspect-cfg");

    assert_eq!(run(&["init", "--key", "alice"], &source, &xdg).0, 0);
    // An instance on which alice may create repositories.
    let creators = vec![run(&["key", "show", "alice"], &source, &xdg)
        .1
        .trim()
        .to_string()];
    let instance_root = tempdir("levcs-inspect-inst");
    let instance_root_for_task = instance_root.clone();
    let (addr, task) =
        rt.block_on(async move { start_instance(instance_root_for_task, creators).await });
    let base_url = format!("http://{addr}/levcs/v1");
    std::fs::write(source.join("README"), b"hello\n").unwrap();
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::write(source.join("nested/file.txt"), b"deep\n").unwrap();
    assert_eq!(run(&["track", "--all"], &source, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "first"], &source, &xdg).0, 0);
    assert_eq!(run(&["instance", "--set", &base_url], &source, &xdg).0, 0);
    assert_eq!(run(&["push"], &source, &xdg).0, 0);

    // Pull the repo_id off disk so we can inspect it remotely.
    let genesis_hex = std::fs::read_to_string(source.join(".levcs/refs/authority/genesis"))
        .unwrap()
        .trim()
        .to_string();
    let genesis_path = source
        .join(".levcs/objects")
        .join(&genesis_hex[..2])
        .join(&genesis_hex[2..]);
    let bytes = std::fs::read(&genesis_path).unwrap();
    let signed = levcs_core::object::SignedObject::parse(&bytes).unwrap();
    let body = levcs_identity::authority::AuthorityBody::parse(&signed.body).unwrap();
    let repo_id_hex = body.repo_id.to_hex();

    // Inspect from a fresh directory so we're really hitting the
    // network path. No `--from`; we'll set the active instance there.
    let probe = tempdir("levcs-inspect-probe");
    assert_eq!(run(&["instance", "--set", &base_url], &probe, &xdg).0, 0);

    // Root inspect: must list the branch tip and the tree at root.
    let (code, stdout, _e) = run(&["inspect", &repo_id_hex], &probe, &xdg);
    assert_eq!(code, 0, "inspect at root must succeed");
    assert!(stdout.contains("repo_id"), "must show repo_id: {stdout}");
    assert!(
        stdout.contains("current authority"),
        "must show authority: {stdout}"
    );
    assert!(stdout.contains("branches:"), "must list branches: {stdout}");
    assert!(stdout.contains("main"), "must show main branch: {stdout}");
    assert!(
        stdout.contains("README"),
        "must list README at root: {stdout}"
    );
    assert!(
        stdout.contains("nested"),
        "must list nested subtree at root: {stdout}"
    );

    // Path inspect: drill into the `nested/` subtree.
    let (code, stdout, _e) = run(&["inspect", &repo_id_hex, "nested"], &probe, &xdg);
    assert_eq!(code, 0, "inspect at nested/ must succeed");
    assert!(
        stdout.contains("file.txt"),
        "must list nested/file.txt: {stdout}"
    );

    task.abort();
    let _ = std::fs::remove_dir_all(&instance_root);
    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&xdg);
    let _ = std::fs::remove_dir_all(&probe);
}
