//! Federation-side commands.
//!
//! These wrap `levcs-client` to talk to a configured instance. The instance
//! URL lives in the repository's `.levcs/config` (TOML) under
//! `instance.url`. A user-global config at `$XDG_CONFIG_HOME/levcs/config.toml`
//! is consulted as a fallback.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use levcs_core::object::{ObjectType, SignedObject};
use levcs_core::refs::Head;
use levcs_core::{Commit, CommitFlags, ObjectId, Repository, ZERO_ID};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::sign::{sign_authority, sign_commit};
use levcs_protocol::{Pack, PushManifest, PushUpdate};

use crate::cli::*;
use crate::ctx::{load_secret, now_micros, open_repo, open_repo_locked};

#[derive(Default, Serialize, Deserialize)]
struct RepoConfig {
    #[serde(default)]
    instance: BTreeMap<String, toml::Value>,
}

fn read_instance_url(repo: &Repository) -> Result<Option<String>> {
    let path = repo.config_path();
    let s = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let cfg: RepoConfig = toml::from_str(&s).unwrap_or_default();
    Ok(cfg
        .instance
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

fn write_instance_url(repo: &Repository, url: &str) -> Result<()> {
    let path = repo.config_path();
    let s = fs::read_to_string(&path).unwrap_or_default();
    let mut cfg: RepoConfig = toml::from_str(&s).unwrap_or_default();
    cfg.instance
        .insert("url".into(), toml::Value::String(url.to_string()));
    let out = toml::to_string_pretty(&cfg)?;
    fs::write(&path, out)?;
    Ok(())
}

fn user_config_path() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("levcs").join("config.toml")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join(".config")
            .join("levcs")
            .join("config.toml")
    } else {
        PathBuf::from(".levcs.toml")
    }
}

#[derive(Default, Serialize, Deserialize)]
struct UserConfig {
    #[serde(default)]
    instances: Vec<String>,
    #[serde(default)]
    active: Option<String>,
}

fn read_user_cfg() -> Result<UserConfig> {
    let p = user_config_path();
    let s = match fs::read_to_string(&p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(e.into()),
    };
    Ok(toml::from_str(&s).unwrap_or_default())
}

fn write_user_cfg(cfg: &UserConfig) -> Result<()> {
    let p = user_config_path();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&p, toml::to_string_pretty(cfg)?)?;
    Ok(())
}

pub fn instance(args: InstanceArgs) -> Result<()> {
    if let Some(url) = args.set {
        if let Ok(repo) = open_repo() {
            let _lock = crate::ctx::lock_repo(&repo)?;
            write_instance_url(&repo, &url)?;
            eprintln!("set repository instance url to {url}");
        } else {
            let mut cfg = read_user_cfg()?;
            cfg.active = Some(url.clone());
            if !cfg.instances.contains(&url) {
                cfg.instances.push(url.clone());
            }
            write_user_cfg(&cfg)?;
            eprintln!("set global active instance to {url}");
        }
        return Ok(());
    }
    if args.info {
        let url = active_instance()?;
        let client = levcs_client::Client::new(url);
        let info = client.instance_info()?;
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    if let Some(url) = args.add {
        let mut cfg = read_user_cfg()?;
        if !cfg.instances.contains(&url) {
            cfg.instances.push(url);
        }
        write_user_cfg(&cfg)?;
        return Ok(());
    }
    if args.list {
        let cfg = read_user_cfg()?;
        for u in cfg.instances {
            let star = if Some(u.clone()) == cfg.active {
                "*"
            } else {
                " "
            };
            println!("{star} {u}");
        }
        return Ok(());
    }
    if let Some(url) = args.remove {
        let mut cfg = read_user_cfg()?;
        cfg.instances.retain(|u| u != &url);
        if cfg.active.as_deref() == Some(url.as_str()) {
            cfg.active = None;
        }
        write_user_cfg(&cfg)?;
        return Ok(());
    }
    eprintln!("usage: levcs instance --set URL | --info | --add URL | --list | --remove URL");
    Ok(())
}

fn active_instance() -> Result<String> {
    if let Ok(repo) = open_repo() {
        if let Some(u) = read_instance_url(&repo)? {
            return Ok(u);
        }
    }
    let cfg = read_user_cfg()?;
    cfg.active
        .ok_or_else(|| anyhow!("no active instance; run `levcs instance --set <URL>`"))
}

pub fn push(args: PushArgs) -> Result<()> {
    let repo = open_repo()?;
    let url = active_instance()?;
    let (_label, sk) = load_secret(args.key.as_deref())?;
    let pk = sk.public();
    let _ = pk;

    let refs_to_push = if args.refs.is_empty() {
        let branch = repo
            .current_branch()?
            .ok_or_else(|| anyhow!("no current branch (detached HEAD)"))?;
        vec![branch]
    } else {
        args.refs
    };
    if args.force {
        eprintln!("force-push: requesting non-fast-forward update; instance will require maintainer or owner role");
    }

    let mut updates = Vec::new();
    let mut needed: Vec<ObjectId> = Vec::new();
    for r in &refs_to_push {
        let new = repo
            .refs
            .read(r)?
            .ok_or_else(|| anyhow!("local ref does not exist: {r}"))?;
        // Build closure of objects reachable from `new`.
        let mut stack = vec![new];
        let mut seen = std::collections::HashSet::<ObjectId>::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Ok(raw) = repo.objects.read_object(id) {
                match raw.object_type {
                    ObjectType::Tree => {
                        if let Ok(t) = levcs_core::Tree::parse_body(&raw.body) {
                            for e in t.entries {
                                stack.push(e.hash);
                            }
                        }
                    }
                    ObjectType::Commit => {
                        if let Ok(c) = Commit::parse_body(&raw.body) {
                            stack.push(c.tree);
                            stack.push(c.authority);
                            stack.extend(c.parents);
                        }
                    }
                    ObjectType::Release => {
                        if let Ok(rel) = levcs_core::Release::parse_body(&raw.body) {
                            stack.push(rel.tree);
                            stack.push(rel.predecessor);
                            stack.push(rel.authority);
                            if !rel.parent_release.is_zero() {
                                stack.push(rel.parent_release);
                            }
                        }
                    }
                    ObjectType::Authority => {
                        if let Ok(b) = AuthorityBody::parse(&raw.body) {
                            if !b.previous_authority.is_zero() {
                                stack.push(b.previous_authority);
                            }
                        }
                    }
                    ObjectType::Blob => {}
                }
            }
        }
        needed.extend(seen.into_iter());
        updates.push(PushUpdate {
            r#ref: r.clone(),
            old_hash: None,
            new_hash: new.to_hex(),
        });
    }
    let auth = repo
        .current_authority()?
        .ok_or_else(|| anyhow!("no current authority"))?;
    let manifest = PushManifest {
        updates,
        authority_hash: auth.to_hex(),
        timestamp: now_micros(),
        force: args.force,
    };
    let mut pack = Pack::new();
    let mut deduped = std::collections::HashSet::new();
    for id in needed {
        if !deduped.insert(id) {
            continue;
        }
        if let Ok(bytes) = repo.objects.read_raw(id) {
            if bytes.len() >= 5 {
                pack.push(bytes[4], bytes);
            }
        }
    }
    let repo_id = compute_repo_id(&repo)?;
    let client = levcs_client::Client::new(url);
    match client.push(&sk, &repo_id, &pack, &manifest) {
        Ok(()) => {}
        Err(levcs_client::ClientError::Server { status: 404, .. }) => {
            // Repo not yet on instance; register it then retry.
            let genesis = repo
                .genesis_authority()?
                .ok_or_else(|| anyhow!("local repo has no genesis authority"))?;
            let bytes = repo.objects.read_raw(genesis)?;
            eprintln!("repo not yet on instance; initialising");
            client.init(&sk, &repo_id, &bytes)?;
            client.push(&sk, &repo_id, &pack, &manifest)?;
        }
        Err(e) => return Err(e.into()),
    }
    eprintln!("pushed {} ref(s)", manifest.updates.len());
    Ok(())
}

pub fn pull(args: PullArgs) -> Result<()> {
    let (repo, _lock) = open_repo_locked()?;
    let url = active_instance()?;
    let client = levcs_client::Client::new(url);
    let _ = args.key;
    let repo_id = compute_repo_id(&repo)?;
    let remote_refs = client.refs(&repo_id)?;
    let want_refs: Vec<String> = if args.refs.is_empty() {
        remote_refs.branches.keys().cloned().collect()
    } else {
        args.refs
    };
    let mut want_ids = Vec::new();
    for r in &want_refs {
        if let Some(h) = remote_refs.branches.get(r) {
            want_ids.push(ObjectId::from_hex(h)?);
        }
    }
    let have_ids: Vec<ObjectId> = repo
        .refs
        .list_branches()?
        .into_iter()
        .map(|(_, id)| id)
        .collect();
    let pack = client.get_pack(&repo_id, &have_ids, &want_ids)?;
    for ent in &pack.entries {
        repo.objects.write_raw(&ent.bytes)?;
    }
    for (r, h) in remote_refs.branches {
        if want_refs.contains(&r) {
            let id = ObjectId::from_hex(&h)?;
            repo.refs
                .write(&format!("refs/remote/origin/branches/{r}"), id)?;
        }
    }
    eprintln!(
        "pulled {} object(s) from {} ref(s)",
        pack.entries.len(),
        want_refs.len()
    );
    Ok(())
}

pub fn fork(args: ForkArgs) -> Result<()> {
    let url = match args.from.clone() {
        Some(u) => u,
        None => active_instance()?,
    };
    let (label, sk) = load_secret(args.key.as_deref())?;
    let pk = sk.public();

    let dest_name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("fork-{}", &args.repo_id[..8.min(args.repo_id.len())]));
    let dest = std::env::current_dir()?.join(&dest_name);
    if dest.exists() {
        bail!("destination already exists: {:?}", dest);
    }

    // 1. Talk to the source instance.
    let client = levcs_client::Client::new(url.clone());
    let info = client.repo_info(&args.repo_id)?;
    if info.repo_id.is_empty() {
        bail!("source instance returned no repo_id");
    }
    let refs = client.refs(&args.repo_id)?;

    // 2. Choose a source tip: prefer "main", else any branch.
    let (source_branch, source_tip_hex) = refs
        .branches
        .iter()
        .find(|(k, _)| *k == "main")
        .or_else(|| refs.branches.iter().next())
        .ok_or_else(|| anyhow!("source repo has no branches; nothing to fork"))?;
    let source_tip = ObjectId::from_hex(source_tip_hex)?;

    // 3. Pull the closure of objects reachable from the source tip and the
    //    current authority.
    let mut want = vec![source_tip];
    if !info.current_authority.is_empty() {
        want.push(ObjectId::from_hex(&info.current_authority)?);
    }
    let pack = client.get_pack(&args.repo_id, &[], &want)?;

    // 4. Initialise the destination repository skeleton (no objects yet).
    let repo = Repository::init_skeleton(&dest)?;
    for ent in &pack.entries {
        repo.objects.write_raw(&ent.bytes)?;
    }

    // 5. Locate the source HEAD commit and its authority.
    let source_commit_signed = repo.read_signed(source_tip)?;
    let source_commit = Commit::from_signed(&source_commit_signed)?;
    let source_auth_signed = repo.read_signed(source_commit.authority)?;
    let source_auth_body = AuthorityBody::parse(&source_auth_signed.body)?;

    // 6. Client-side authorization check (the receiving instance also enforces
    //    this via verify_fork during push). Per §3.5.2.
    if !source_auth_body.public_read() && source_auth_body.find_member(&pk).is_none() {
        bail!(
            "source repository is not public-read and your key {} has no access; \
             ask an owner to grant you reader role first",
            pk
        );
    }

    // 7. Generate the new genesis authority. Sole owner is the forking user.
    let now = now_micros();
    let mut new_auth_body = AuthorityBody {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: now,
        members: vec![MemberEntry {
            key: pk,
            handle: label.clone(),
            role: Role::Owner,
            added_micros: now,
            added_by: pk,
        }],
        policy: vec![
            PolicyEntry {
                key: "public_read".into(),
                value: vec![0x01],
            },
            PolicyEntry {
                key: "require_signed_releases".into(),
                value: vec![0x01],
            },
            PolicyEntry {
                key: "allowed_handlers".into(),
                value: b"builtin".to_vec(),
            },
        ],
    };
    new_auth_body.normalize()?;
    new_auth_body.assign_genesis_repo_id()?;
    if new_auth_body.repo_id == source_auth_body.repo_id {
        bail!("derived repo_id collides with source; refusing to fork");
    }
    let new_auth_signed = sign_authority(&new_auth_body, &sk)?;
    let new_auth_id = repo.write_signed(&new_auth_signed)?;

    // 8. Build the fork commit's tree: source's tree, with .levcs/authority
    //    pointing at the new genesis.
    let new_tree_id =
        crate::tree_helpers::put_authority_in_tree(&repo, source_commit.tree, new_auth_id)?;

    // 9. Construct and sign the fork commit.
    let flags = CommitFlags(CommitFlags::MODIFIES_AUTHORITY.0 | CommitFlags::FORK.0);
    let fork_commit = Commit {
        tree: new_tree_id,
        parents: vec![source_tip],
        authority: new_auth_id,
        author_key: pk.0,
        timestamp_micros: now_micros(),
        flags,
        message: format!(
            "fork from blake3:{} (branch {}, tip {})",
            args.repo_id, source_branch, source_tip
        ),
    };
    let fork_signed = sign_commit(fork_commit, &sk)?;
    let fork_id = repo.write_signed(&fork_signed)?;

    // 10. Materialise the working tree, then wire up refs and HEAD, so a
    //     checkout refused part way leaves no ref naming a tree that was
    //     never written.
    repo.checkout_tree(source_commit.tree, &dest)?;
    repo.set_genesis_authority(new_auth_id)?;
    repo.set_current_authority(new_auth_id)?;
    let main_ref = "refs/branches/main".to_string();
    repo.refs.write(&main_ref, fork_id)?;
    repo.refs.write_head(&Head::Branch(main_ref.clone()))?;

    eprintln!(
        "forked {} into {:?}\n  new repo_id  = blake3:{}\n  fork commit  = {}\n  source tip   = {} ({})\n  source auth  = {}",
        args.repo_id,
        dest,
        new_auth_body.repo_id,
        fork_id,
        source_tip,
        source_branch,
        source_commit.authority,
    );
    Ok(())
}

pub fn inspect(args: InspectArgs) -> Result<()> {
    use levcs_core::object::ObjectType;
    use levcs_core::{Commit, EntryType, ObjectId, Tree};

    let url = match args.from {
        Some(u) => u,
        None => active_instance()?,
    };
    let client = levcs_client::Client::new(url);

    // Header: repo_info + authority hash + branch heads. This is the
    // §7.3.5 "fetches the current authority, branch heads" data; we
    // print it as a small structured summary so users get a quick
    // snapshot before deciding to fork or clone.
    let info = client.repo_info(&args.repo_id)?;
    println!("repo_id           : {}", args.repo_id);
    if !info.current_authority.is_empty() {
        println!("current authority : {}", info.current_authority);
    }
    println!();

    let refs = client.refs(&args.repo_id)?;
    if !refs.branches.is_empty() {
        println!("branches:");
        for (name, hash) in &refs.branches {
            println!("  {name:<24} {hash}");
        }
    }
    if !refs.releases.is_empty() {
        println!("releases:");
        for (name, hash) in &refs.releases {
            println!("  {name:<24} {hash}");
        }
    }
    println!();

    // Tree at <path> (default root). §7.3.5 says "tree at <path>
    // (default: root)" — that's the contents listing the user can
    // browse without pulling. We resolve `main` (then any branch) to
    // a commit, walk to the requested path, and print one line per
    // entry. Blobs are listed but not fetched — the point of inspect
    // is to be a quick peek without bulk transfer.
    let tip_branch = refs
        .branches
        .iter()
        .find(|(n, _)| *n == "main")
        .or_else(|| refs.branches.iter().next());
    let Some((tip_name, tip_hash)) = tip_branch else {
        // Bare repo with no branches; nothing more to show.
        return Ok(());
    };
    let tip_id = ObjectId::from_hex(tip_hash)?;
    let raw = client.get_object(&args.repo_id, tip_id)?;
    let signed = levcs_core::object::SignedObject::parse(&raw)?;
    let commit = Commit::from_signed(&signed)?;

    let path = args.path.unwrap_or_default();
    let path_components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let display_path = if path_components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path_components.join("/"))
    };
    println!("tree at {display_path} (branch {tip_name} → {tip_id}):");

    // Resolve the path one segment at a time over the wire — each step
    // is one /objects/<hash> fetch.
    let mut current_tree_id = commit.tree;
    for comp in &path_components {
        let raw = client.get_object(&args.repo_id, current_tree_id)?;
        let parsed = levcs_core::object::RawObject::parse(&raw)?;
        if parsed.object_type != ObjectType::Tree {
            anyhow::bail!("path component {:?} is not a tree", comp);
        }
        let tree = Tree::parse_body(&parsed.body)?;
        let entry = tree
            .entries
            .iter()
            .find(|e| &e.name == *comp)
            .ok_or_else(|| anyhow!("path not found: {comp}"))?;
        match entry.entry_type {
            EntryType::Tree => {
                current_tree_id = entry.hash;
            }
            EntryType::Blob => {
                // Path resolves to a single blob — list it as one entry.
                println!("  blob  {:>10}  {}", "?", entry.name);
                return Ok(());
            }
        }
    }
    let raw = client.get_object(&args.repo_id, current_tree_id)?;
    let parsed = levcs_core::object::RawObject::parse(&raw)?;
    let tree = Tree::parse_body(&parsed.body)?;
    for entry in &tree.entries {
        let kind = match entry.entry_type {
            EntryType::Tree => "tree",
            EntryType::Blob => "blob",
        };
        println!("  {kind}  {}  {}", entry.hash, entry.name);
    }
    Ok(())
}

pub fn deploy(args: DeployArgs) -> Result<()> {
    use std::net::TcpListener;

    let repo = open_repo()?;
    let (_label, sk) = load_secret(args.key.as_deref())?;
    let recipient_pub = levcs_identity::keys::PublicKey::parse_levcs(&args.recipient_key)
        .map_err(|e| anyhow!("invalid recipient_key: {e}"))?;

    // Build the manifest + pack we'll ship once a dialer connects. Doing
    // this up-front means the listener can answer instantly and lets us
    // surface any local error (missing authority, empty repo) before we
    // bind a port.
    let (manifest, pack) = build_deploy_archive(&repo, args.release)?;
    let pack_bytes = pack.encode();

    let listener =
        TcpListener::bind(&args.listen).with_context(|| format!("bind {}", args.listen))?;
    let local = listener.local_addr()?;
    eprintln!(
        "deploy listening on {local}\n  recipient = {}\n  send  {} branch(es), {} release(s), {} object(s) ({} bytes packed)",
        recipient_pub.to_levcs(),
        manifest.branches.len(),
        manifest.releases.len(),
        pack.entries.len(),
        pack_bytes.len(),
    );
    eprintln!(
        "  share with peer:  levcs dial {} {}",
        local,
        recipient_pub.to_levcs()
    );

    // One dialer, then exit. The spec characterizes this as a one-shot
    // transfer, not a long-lived service — repeated transfers should run
    // the command again so the user is in the loop on each session.
    let (stream, peer_addr) = listener.accept()?;
    eprintln!("dialer connected from {peer_addr}");

    let mut session = match levcs_protocol::p2p::handshake_listen(stream, &sk, &recipient_pub) {
        Ok(s) => s,
        Err(e) => bail!("handshake failed: {e}"),
    };
    session
        .send_manifest(&manifest)
        .map_err(|e| anyhow!("send manifest: {e}"))?;
    session
        .send_pack(&pack_bytes)
        .map_err(|e| anyhow!("send pack: {e}"))?;
    session.send_done().map_err(|e| anyhow!("send done: {e}"))?;
    eprintln!("deploy complete");
    Ok(())
}

/// Assemble the archive a deploy session sends: manifest of refs and tip
/// hashes plus a pack containing the closure of all referenced objects.
/// Splitting this out keeps the listener loop simple — it never has to
/// touch the repository once a dialer is on the line.
fn build_deploy_archive(
    repo: &Repository,
    release_only: bool,
) -> Result<(levcs_protocol::p2p::DeployManifest, Pack)> {
    let repo_id = compute_repo_id(repo)?;
    let genesis = repo
        .genesis_authority()?
        .ok_or_else(|| anyhow!("repository has no genesis authority"))?;
    let auth = repo
        .current_authority()?
        .ok_or_else(|| anyhow!("no current authority"))?;

    let releases = repo.refs.list_releases()?;
    let branches = if release_only {
        Vec::new()
    } else {
        repo.refs.list_branches()?
    };
    if branches.is_empty() && releases.is_empty() {
        bail!(
            "nothing to deploy: repository has no {}",
            if release_only {
                "releases"
            } else {
                "branches or releases"
            }
        );
    }

    let mut needed = std::collections::HashSet::<ObjectId>::new();
    let mut branch_map = BTreeMap::new();
    for (name, id) in &branches {
        walk_closure(repo, *id, &mut needed);
        branch_map.insert(name.clone(), id.to_hex());
    }
    let mut release_map = BTreeMap::new();
    for (name, id) in &releases {
        walk_closure(repo, *id, &mut needed);
        release_map.insert(name.clone(), id.to_hex());
    }
    walk_closure(repo, auth, &mut needed);
    walk_closure(repo, genesis, &mut needed);

    let mut pack = Pack::new();
    for id in needed {
        if let Ok(bytes) = repo.objects.read_raw(id) {
            if bytes.len() >= 5 {
                pack.push(bytes[4], bytes);
            }
        }
    }
    let manifest = levcs_protocol::p2p::DeployManifest {
        repo_id,
        mode: if release_only {
            "release".into()
        } else {
            "all".into()
        },
        branches: branch_map,
        releases: release_map,
        authority_hash: auth.to_hex(),
        genesis_authority: genesis.to_hex(),
        timestamp_micros: now_micros(),
    };
    Ok((manifest, pack))
}

/// Move the local repository to a different instance, preserving repo_id
/// and full history (§5.7). One-shot orchestration:
///   1. /init the destination with the genesis authority object,
///   2. push every branch and release in a single signed manifest,
///      with a pack containing the closure of all refs and the current
///      authority chain.
/// Idempotent at the wire level: if the destination already has the
/// repo_id (e.g. a previous attempt got partway), init returns 409 and
/// we skip straight to push.
pub fn migrate(args: MigrateArgs) -> Result<()> {
    let repo = open_repo()?;
    let (_label, sk) = load_secret(args.key.as_deref())?;
    // Locked after the key, so a passphrase prompt holds no other writer.
    let _lock = crate::ctx::lock_repo(&repo)?;
    let repo_id = compute_repo_id(&repo)?;
    let client = levcs_client::Client::new(args.to.clone());

    // Step 1: ensure the destination has the repository, initialised from
    // genesis. /init is idempotent in spirit — duplicate calls return 409,
    // which we treat as "already there, carry on".
    let genesis_id = repo
        .genesis_authority()?
        .ok_or_else(|| anyhow!("local repo has no genesis authority"))?;
    let genesis_bytes = repo.objects.read_raw(genesis_id)?;
    match client.init(&sk, &repo_id, &genesis_bytes) {
        Ok(()) => eprintln!("initialised {repo_id} on {}", args.to),
        Err(levcs_client::ClientError::Server { status: 409, .. }) => {
            eprintln!("repo already exists on destination; skipping init");
        }
        Err(e) => return Err(e.into()),
    }

    // Step 2: collect every ref we want to advance on the destination —
    // both branches and releases — and union their reachable closures
    // into a single pack. Authority chain comes along automatically as a
    // dependency of every commit/release.
    let branches = repo.refs.list_branches()?;
    let releases = repo.refs.list_releases()?;
    if branches.is_empty() && releases.is_empty() {
        bail!("nothing to migrate: repository has no branches or releases");
    }

    let mut updates = Vec::with_capacity(branches.len() + releases.len());
    let mut needed = std::collections::HashSet::<ObjectId>::new();
    for (name, id) in &branches {
        walk_closure(&repo, *id, &mut needed);
        updates.push(PushUpdate {
            r#ref: format!("refs/branches/{name}"),
            old_hash: None,
            new_hash: id.to_hex(),
        });
    }
    for (name, id) in &releases {
        walk_closure(&repo, *id, &mut needed);
        updates.push(PushUpdate {
            r#ref: format!("refs/releases/{name}"),
            old_hash: None,
            new_hash: id.to_hex(),
        });
    }

    let auth = repo
        .current_authority()?
        .ok_or_else(|| anyhow!("no current authority"))?;
    walk_closure(&repo, auth, &mut needed);

    let mut pack = Pack::new();
    for id in needed {
        if let Ok(bytes) = repo.objects.read_raw(id) {
            if bytes.len() >= 5 {
                pack.push(bytes[4], bytes);
            }
        }
    }
    let manifest = PushManifest {
        updates,
        authority_hash: auth.to_hex(),
        timestamp: now_micros(),
        // Mirror replication never force-pushes — every update through
        // here is by construction a fast-forward (the source has the
        // commits the destination is missing).
        force: false,
    };

    // Step 3: push. The destination verifies signatures end-to-end against
    // the same authority chain we just sent — there's no trust delegation
    // to the new instance, only authentication of the pusher.
    client.push(&sk, &repo_id, &pack, &manifest)?;
    eprintln!(
        "migrated {repo_id}: {} branch(es), {} release(s), {} object(s)",
        branches.len(),
        releases.len(),
        pack.entries.len()
    );

    if args.set_active {
        write_instance_url(&repo, &args.to)?;
        eprintln!("active instance for this repo set to {}", args.to);
    } else {
        eprintln!(
            "(run `levcs instance --set {}` to repoint future operations)",
            args.to
        );
    }
    Ok(())
}

/// Reachability walk shared by push() and migrate(). Inserts every object
/// transitively referenced from `start` into `out`, including blobs.
fn walk_closure(repo: &Repository, start: ObjectId, out: &mut std::collections::HashSet<ObjectId>) {
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        if !out.insert(id) {
            continue;
        }
        let raw = match repo.objects.read_object(id) {
            Ok(r) => r,
            Err(_) => continue,
        };
        match raw.object_type {
            ObjectType::Tree => {
                if let Ok(t) = levcs_core::Tree::parse_body(&raw.body) {
                    for e in t.entries {
                        stack.push(e.hash);
                    }
                }
            }
            ObjectType::Commit => {
                if let Ok(c) = Commit::parse_body(&raw.body) {
                    stack.push(c.tree);
                    stack.push(c.authority);
                    stack.extend(c.parents);
                }
            }
            ObjectType::Release => {
                if let Ok(rel) = levcs_core::Release::parse_body(&raw.body) {
                    stack.push(rel.tree);
                    stack.push(rel.predecessor);
                    stack.push(rel.authority);
                    if !rel.parent_release.is_zero() {
                        stack.push(rel.parent_release);
                    }
                }
            }
            ObjectType::Authority => {
                if let Ok(b) = AuthorityBody::parse(&raw.body) {
                    if !b.previous_authority.is_zero() {
                        stack.push(b.previous_authority);
                    }
                }
            }
            ObjectType::Blob => {}
        }
    }
}

pub fn dial(args: DialArgs) -> Result<()> {
    use std::net::TcpStream;

    let (_label, sk) = load_secret(args.key.as_deref())?;
    let sender_pub = levcs_identity::keys::PublicKey::parse_levcs(&args.sender_key)
        .map_err(|e| anyhow!("invalid sender_key: {e}"))?;

    let stream = TcpStream::connect(&args.sender_host)
        .with_context(|| format!("connect {}", args.sender_host))?;
    eprintln!("dialing {} as {}", args.sender_host, sender_pub.to_levcs());

    let mut session = match levcs_protocol::p2p::handshake_dial(stream, &sk, &sender_pub) {
        Ok(s) => s,
        Err(e) => bail!("handshake failed: {e}"),
    };
    let manifest = session
        .recv_manifest()
        .map_err(|e| anyhow!("recv manifest: {e}"))?;
    let pack_bytes = session.recv_pack().map_err(|e| anyhow!("recv pack: {e}"))?;
    session.recv_done().map_err(|e| anyhow!("recv done: {e}"))?;
    let pack = Pack::decode(&pack_bytes).map_err(|e| anyhow!("decode pack: {e}"))?;
    eprintln!(
        "received {} object(s); manifest reports {} branch(es), {} release(s)",
        pack.entries.len(),
        manifest.branches.len(),
        manifest.releases.len()
    );

    // Pick a destination directory. Default is `<repo_id_prefix>` in cwd —
    // mirrors the convention `levcs fork` uses.
    let dest = match args.path {
        Some(p) => p,
        None => std::env::current_dir()?.join(format!(
            "dial-{}",
            &manifest.repo_id[..8.min(manifest.repo_id.len())]
        )),
    };
    if dest.exists() {
        bail!("destination already exists: {:?}", dest);
    }
    let repo = Repository::init_skeleton(&dest)?;

    // Write objects first so verify_commit / verify_release can read them
    // by hash. Each entry is an already-framed SignedObject — write_raw
    // re-hashes and rejects content that doesn't match its declared id.
    for ent in &pack.entries {
        repo.objects.write_raw(&ent.bytes)?;
    }

    // Cross-check the manifest's repo_id against the genesis authority we
    // just received. The recipient never trusts the manifest's word for it.
    let genesis_id = ObjectId::from_hex(&manifest.genesis_authority)
        .map_err(|_| anyhow!("manifest genesis_authority not a valid hash"))?;
    let genesis_signed = repo.read_signed(genesis_id)?;
    let genesis_body = AuthorityBody::parse(&genesis_signed.body)?;
    let derived_repo_id = genesis_body.repo_id.to_hex();
    if derived_repo_id != manifest.repo_id {
        bail!(
            "manifest repo_id {} does not match genesis-derived {}",
            manifest.repo_id,
            derived_repo_id
        );
    }

    // Verify each tip end-to-end. verify_commit / verify_release walk the
    // authority chain and the embedded signatures — refuse to advance any
    // ref whose tip can't be verified, even if the bytes hash-match.
    for (_name, hex) in &manifest.branches {
        let id = ObjectId::from_hex(hex)?;
        levcs_identity::verify::verify_commit(&repo.objects, id, None)
            .map_err(|e| anyhow!("verify branch tip {hex}: {e}"))?;
    }
    for (_name, hex) in &manifest.releases {
        let id = ObjectId::from_hex(hex)?;
        levcs_identity::verify::verify_release(&repo.objects, id)
            .map_err(|e| anyhow!("verify release {hex}: {e}"))?;
    }

    // HEAD on main if present, otherwise any branch we got. Releases-only
    // archives leave HEAD detached at the latest release's predecessor —
    // there's no branch to point at. The working tree is materialised
    // first, so a checkout refused part way leaves no ref naming a tree
    // that was never written.
    let head = if let Some((name, hex)) = manifest
        .branches
        .iter()
        .find(|(k, _)| k.as_str() == "main")
        .or_else(|| manifest.branches.iter().next())
    {
        let id = ObjectId::from_hex(hex)?;
        let commit = Commit::from_signed(&repo.read_signed(id)?)?;
        Some((Head::Branch(format!("refs/branches/{name}")), commit.tree))
    } else if let Some((_name, hex)) = manifest.releases.iter().next() {
        let id = ObjectId::from_hex(hex)?;
        let rel = levcs_core::Release::from_signed(&repo.read_signed(id)?)?;
        Some((Head::Detached(id), rel.tree))
    } else {
        None
    };
    if let Some((_, tree)) = &head {
        repo.checkout_tree(*tree, &dest)?;
    }

    // Now wire up refs. Authority pointers come from the manifest; we
    // already have those objects in the store and verified them through
    // the commit/release walks.
    repo.set_genesis_authority(genesis_id)?;
    let auth_id = ObjectId::from_hex(&manifest.authority_hash)?;
    repo.set_current_authority(auth_id)?;
    for (name, hex) in &manifest.branches {
        let id = ObjectId::from_hex(hex)?;
        repo.refs.write(&format!("refs/branches/{name}"), id)?;
    }
    for (name, hex) in &manifest.releases {
        let id = ObjectId::from_hex(hex)?;
        repo.refs.write(&format!("refs/releases/{name}"), id)?;
    }
    if let Some((h, _)) = head {
        repo.refs.write_head(&h)?;
    }

    eprintln!(
        "dial complete: repository at {:?}\n  repo_id    = blake3:{}\n  authority  = {}",
        dest, derived_repo_id, manifest.authority_hash
    );
    Ok(())
}

fn compute_repo_id(repo: &Repository) -> Result<String> {
    let genesis = repo
        .genesis_authority()?
        .ok_or_else(|| anyhow!("repository has no genesis authority"))?;
    let signed = repo.read_signed(genesis)?;
    if signed.object_type != ObjectType::Authority {
        bail!("genesis is not an authority");
    }
    let body = AuthorityBody::parse(&signed.body)?;
    Ok(body.repo_id.to_hex())
}

#[allow(dead_code)]
fn _unused(_: SignedObject) {}
