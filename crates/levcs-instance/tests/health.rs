//! `/health` operational endpoint smoke test.
//!
//! The reverse proxy in front of a deployed instance probes this for
//! liveness, so it has to be (a) cheap, (b) reachable without auth,
//! and (c) outside the `/levcs/v1` namespace so a future API change
//! can't accidentally affect it.

use std::net::SocketAddr;
use std::path::PathBuf;

use levcs_instance::{router, AppState, InstanceConfig};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_returns_ok_without_auth() {
    let root = tempdir("levcs-health");
    let cfg = InstanceConfig {
        root: root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
        creators: Vec::new(),
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

    let resp = tokio::task::spawn_blocking(move || {
        reqwest::blocking::get(format!("http://{addr}/health"))
            .unwrap()
            .text()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(resp.contains("\"status\""));
    assert!(resp.contains("\"ok\""));

    task.abort();
    let _ = std::fs::remove_dir_all(root);
}
