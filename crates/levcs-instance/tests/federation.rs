//! Federation integration test: spin up an in-process instance, exercise the
//! /instance/info and /repos/{id}/init paths over HTTP via the client.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use levcs_core::ZERO_ID;
use levcs_identity::authority::{AuthorityBody, MemberEntry, PolicyEntry, Role};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::sign_authority;
use levcs_instance::{serve, AppState, InstanceConfig};

fn tempdir() -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("levcs-fed-{n}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instance_info_and_init_roundtrip() {
    let root = tempdir();
    let config = InstanceConfig {
        root: root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: vec!["builtin".into()],
        mirrors: Vec::new(),
    };
    let state = AppState::new(config);
    // Bind to an ephemeral port.
    let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = levcs_instance::router(state);
    let serve_task = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let base = format!("http://{addr}/levcs/v1");
    // /instance/info via plain reqwest
    let client = reqwest::Client::new();
    let info: serde_json::Value = client
        .get(format!("{base}/instance/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["software"], "levcs-instance");

    // POST /repos/{id}/init
    let sk = SecretKey::generate();
    let pk = sk.public();
    let now = 1_700_000_000_000_000;
    let mut body = AuthorityBody {
        schema_version: 1,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: now,
        members: vec![MemberEntry {
            key: pk,
            handle: "alice".into(),
            role: Role::Owner,
            added_micros: now,
            added_by: pk,
        }],
        policy: vec![PolicyEntry { key: "public_read".into(), value: vec![0x01] }],
    };
    body.normalize().unwrap();
    body.assign_genesis_repo_id().unwrap();
    let signed = sign_authority(&body, &sk).unwrap();
    let bytes = signed.serialize();
    let repo_id = body.repo_id.to_hex();

    // Sign request manually via levcs-protocol's sign_request.
    use levcs_protocol::auth::{sign_request, AuthRequest};
    let path = format!("/repos/{repo_id}/init");
    let req = AuthRequest { method: "POST", path_with_query: &path, body: &bytes };
    let (key, ts, nonce, sig) = sign_request(&sk, &req).unwrap();
    let res = client
        .post(format!("{base}{path}"))
        .header("LeVCS-Key", key)
        .header("LeVCS-Timestamp", ts)
        .header("LeVCS-Nonce", nonce)
        .header("LeVCS-Signature", sig)
        .header("Content-Type", "application/octet-stream")
        .body(bytes.clone())
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "init returned {}: {}", res.status(), res.text().await.unwrap());

    // /repos/{id}/info should now succeed
    let info: serde_json::Value = client
        .get(format!("{base}/repos/{repo_id}/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["repo_id"], repo_id);

    serve_task.abort();
    let _ = std::fs::remove_dir_all(root);
    let _ = serve;
}
