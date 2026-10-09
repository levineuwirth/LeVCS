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

/// The instance this repository is a workspace of, from its own
/// `.levcs/config`. A config that cannot be read or parsed is an error,
/// never read as naming no instance: whether this repository's refs are
/// its published state turns on it (`publish::mode`). A malformed config
/// used to read as empty, and so turned a workspace standalone.
pub(crate) fn read_instance_url(repo: &Repository) -> Result<Option<String>> {
    let path = repo.config_path();
    let s = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let cfg: RepoConfig =
        toml::from_str(&s).map_err(|e| anyhow!("cannot read {}: {e}", path.display()))?;
    match cfg.instance.get("url") {
        None => Ok(None),
        Some(toml::Value::String(u)) => Ok(Some(u.clone())),
        Some(_) => bail!(
            "cannot read {}: [instance] url is not a string",
            path.display()
        ),
    }
}

/// Make this repository a workspace of the instance at `url`. It is marked
/// so first, durably: see `publish::mode`. A config that cannot be parsed
/// is refused, not rewritten.
fn write_instance_url(repo: &Repository, url: &str) -> Result<()> {
    let path = repo.config_path();
    let s = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut cfg: RepoConfig = toml::from_str(&s).map_err(|e| {
        anyhow!(
            "cannot read {}: {e}; not rewriting a config that cannot be read",
            path.display()
        )
    })?;
    crate::publish::mark_workspace(repo)?;
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
    let sk = std::sync::Arc::new(sk);

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
    let repo_id = compute_repo_id(&repo)?;
    // Reads are signed, so that a member can push to a private repository.
    let client = levcs_client::Client::new(url).with_reader(sk.clone());

    // What the instance holds: the value each update is expected to replace,
    // and what need not be sent. A push used to expect every ref to be
    // absent, so each push after a ref's first was refused as stale (audit
    // H11), and it sent the whole history every time.
    let remote = match client.repo_info(&repo_id) {
        Ok(info) => Some(info),
        Err(levcs_client::ClientError::Server { status: 404, .. }) => None,
        Err(e) => return Err(e.into()),
    };
    let mut updates = Vec::new();
    let mut tips = Vec::new();
    for r in &refs_to_push {
        let new = repo
            .refs
            .read(r)?
            .ok_or_else(|| anyhow!("local ref does not exist: {r}"))?;
        let old = match &remote {
            Some(info) => remote_value(info, r)?,
            None => None,
        };
        updates.push(PushUpdate {
            r#ref: r.clone(),
            old_hash: old.map(|o| o.to_hex()),
            new_hash: new.to_hex(),
        });
        tips.push(new);
    }
    // What the instance's refs reach, as far as this repository knows it,
    // is not sent again.
    let mut has = std::collections::HashSet::new();
    if let Some(info) = &remote {
        let held = info
            .branches
            .values()
            .chain(info.releases.values())
            .chain([&info.current_authority]);
        for hex in held {
            if let Ok(id) = ObjectId::from_hex(hex) {
                if repo.objects.contains(id) {
                    walk_closure(&repo, id, &mut has);
                }
            }
        }
    }
    let mut reached = has.clone();
    for tip in &tips {
        walk_closure(&repo, *tip, &mut reached);
    }
    let mut pack = Pack::new();
    for id in reached.difference(&has) {
        if let Ok(bytes) = repo.objects.read_raw(*id) {
            if bytes.len() >= 5 {
                pack.push(bytes[4], bytes);
            }
        }
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

    // Measured before anything is sent, against what the instance says it
    // takes, which it enforces whatever is checked here.
    let size = levcs_client::PushSize::of(&pack, &manifest)?;
    // A failure to ask is a failure, not a push without a check: only an
    // instance that answers, and does not say, is pushed to unchecked.
    let limits = client.instance_info()?.limits;
    if args.dry_run {
        println!(
            "would push {} ref(s) to {}: {} object(s), {} bytes decoded, the largest {} bytes; a request of {} bytes",
            manifest.updates.len(),
            if remote.is_some() { "the instance" } else { "a new repository on the instance" },
            size.objects,
            size.decoded,
            size.largest,
            size.body
        );
        match &limits {
            Some(l) => match size.over(l) {
                Some(why) => println!("the instance would refuse it: {why}"),
                None => println!(
                    "within the instance's limits: {} bytes a request, {} objects, {} bytes decoded, {} bytes an object",
                    l.max_push_bytes, l.max_pack_objects, l.max_pack_bytes, l.max_object_bytes
                ),
            },
            None => println!("the instance does not say what it takes"),
        }
        return Ok(());
    }
    if let Some(why) = limits.as_ref().and_then(|l| size.over(l)) {
        bail!("{why}; nothing was sent");
    }

    if remote.is_none() {
        let genesis = repo
            .genesis_authority()?
            .ok_or_else(|| anyhow!("local repo has no genesis authority"))?;
        let bytes = repo.objects.read_raw(genesis)?;
        eprintln!("repo not yet on instance; initialising");
        match client.init(&sk, &repo_id, &bytes) {
            Ok(()) => {}
            Err(levcs_client::ClientError::Server { status: 409, .. }) => {
                bail!("the instance holds this repository, but does not let this key read it")
            }
            Err(e) => return Err(e.into()),
        }
    }
    client.push(&sk, &repo_id, &pack, &manifest)?;
    eprintln!(
        "pushed {} ref(s): {} object(s)",
        manifest.updates.len(),
        size.objects
    );
    Ok(())
}

/// What the instance's `info` says `name` holds: a branch or a release,
/// named in full (`refs/branches/<b>`, `refs/releases/<r>`), where `info`
/// names them short.
fn remote_value(info: &levcs_protocol::InfoResponse, name: &str) -> Result<Option<ObjectId>> {
    let held = if let Some(b) = name.strip_prefix("refs/branches/") {
        info.branches.get(b)
    } else if let Some(r) = name.strip_prefix("refs/releases/") {
        info.releases.get(r)
    } else {
        bail!("only branches and releases are pushed, not {name}");
    };
    held.map(|h| ObjectId::from_hex(h))
        .transpose()
        .map_err(|e| anyhow!("the instance says {name} holds {e}"))
}

/// A client for `url` that signs its reads with the key `label` names: a
/// private repository is served only to its members. Without one, reads
/// are anonymous, which reads a public repository.
fn reader(url: String, label: Option<&str>) -> Result<levcs_client::Client> {
    Ok(match label {
        Some(label) => levcs_client::Client::new(url)
            .with_reader(std::sync::Arc::new(load_secret(Some(label))?.1)),
        None => levcs_client::Client::new(url),
    })
}

/// A repository id as given: 64 lowercase hex digits, with or without the
/// `blake3:` this tool prints before one.
fn repo_id_arg(given: &str) -> Result<String> {
    let id = given.strip_prefix("blake3:").unwrap_or(given);
    match ObjectId::from_hex(id) {
        Ok(parsed) if parsed.to_hex() == id => Ok(id.to_string()),
        _ => bail!("{given:?} is not a repository id (64 lowercase hex digits)"),
    }
}

/// An id the instance gave, as `what`.
fn id_from(what: &str, hex: &str) -> Result<ObjectId> {
    ObjectId::from_hex(hex)
        .map_err(|_| anyhow!("the instance gave {what} as {hex:?}, which is not an object id"))
}

/// What the instance says it holds of `repo_id`. A private repository that
/// the reader may not read is answered as a missing one.
fn published(
    client: &levcs_client::Client,
    url: &str,
    repo_id: &str,
) -> Result<levcs_protocol::InfoResponse> {
    let info = match client.repo_info(repo_id) {
        Ok(info) => info,
        Err(levcs_client::ClientError::Server { status: 404, .. }) => bail!(
            "{url} has no repository {repo_id}, or none it lets this reader see \
             (a private repository is read with --key)"
        ),
        Err(e) => return Err(e.into()),
    };
    if info.repo_id != repo_id {
        bail!(
            "asked {url} for repository {repo_id}, and it answered for {:?}",
            info.repo_id
        );
    }
    Ok(info)
}

/// Fetch what the instance's branches hold, check it (Rule R; see
/// `receive`), and record it under `refs/remote/origin/`: a record of the
/// instance's state, not this repository's.
pub fn pull(args: PullArgs) -> Result<()> {
    let (repo, _lock) = open_repo_locked()?;
    let url = active_instance()?;
    let client = reader(url.clone(), args.key.as_deref())?;
    let repo_id = compute_repo_id(&repo)?;
    let genesis = repo
        .genesis_authority()?
        .ok_or_else(|| anyhow!("this repository has no genesis authority"))?;
    let info = published(&client, &url, &repo_id)?;
    let current = id_from("its current authority", &info.current_authority)?;
    let names: Vec<String> = if args.refs.is_empty() {
        info.branches.keys().cloned().collect()
    } else {
        args.refs.clone()
    };
    let mut roots = Vec::new();
    for name in &names {
        let hex = info
            .branches
            .get(name)
            .ok_or_else(|| anyhow!("{url} has no branch {name:?} in {repo_id}"))?;
        let r = format!("refs/remote/origin/branches/{name}");
        levcs_core::refs::validate_ref_name(&r)?;
        roots.push((r, id_from(&format!("branch {name:?}"), hex)?));
    }
    // What this repository holds already, which need not be sent again.
    let mut have: Vec<ObjectId> = repo
        .refs
        .list_all()?
        .into_iter()
        .filter(|(n, _)| {
            n.starts_with("refs/branches/") || n.starts_with("refs/remote/origin/branches/")
        })
        .map(|(_, id)| id)
        .filter(|id| repo.objects.contains(*id))
        .collect();
    have.sort();
    have.dedup();
    let received = crate::receive::receive(
        &client,
        &repo_id,
        genesis,
        current,
        &roots,
        &have,
        Some(&repo.objects),
    )?;
    received.write(&repo.objects)?;
    for (r, id) in &roots {
        repo.refs.write(r, *id)?;
    }
    eprintln!(
        "pulled {} ref(s) into refs/remote/origin/: {} new object(s), all of their history \
         verified against this repository's genesis",
        roots.len(),
        received.len()
    );
    Ok(())
}

/// A new workspace of the instance holding `repo_id`, with its branches,
/// releases and authority as the instance publishes them, checked first
/// (Rule R; see `receive`), and the working tree of its `main`.
pub fn clone(args: CloneArgs) -> Result<()> {
    let repo_id = repo_id_arg(&args.repo_id)?;
    let url = match &args.from {
        Some(u) => u.clone(),
        None => active_instance()?,
    };
    let dest = match &args.path {
        Some(p) => p.clone(),
        None => std::env::current_dir()?.join(&repo_id[..8]),
    };
    if dest.exists() {
        bail!("destination already exists: {}", dest.display());
    }
    let client = reader(url.clone(), args.key.as_deref())?;
    let info = published(&client, &url, &repo_id)?;
    let genesis = id_from("its genesis authority", &info.genesis_authority)?;
    let current = id_from("its current authority", &info.current_authority)?;
    let mut refs = Vec::new();
    for (kind, named) in [("branches", &info.branches), ("releases", &info.releases)] {
        for (name, hex) in named {
            let r = format!("refs/{kind}/{name}");
            levcs_core::refs::validate_ref_name(&r)?;
            refs.push((r, id_from(&format!("{kind} {name:?}"), hex)?));
        }
    }
    let mut roots = vec![
        ("refs/authority/genesis".to_string(), genesis),
        ("refs/authority/current".to_string(), current),
    ];
    roots.extend(refs.iter().cloned());
    let received = crate::receive::receive(&client, &repo_id, genesis, current, &roots, &[], None)?;

    // Only now is anything written. A clone that fails from here on is
    // removed whole: it is a directory this run made.
    struct Unfinished(Option<PathBuf>);
    impl Drop for Unfinished {
        fn drop(&mut self) {
            if let Some(dir) = self.0.take() {
                let _ = fs::remove_dir_all(dir);
            }
        }
    }
    fs::create_dir(&dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut unfinished = Unfinished(Some(dest.clone()));
    let repo = Repository::init_skeleton(&dest)?;
    write_instance_url(&repo, &url)?;
    received.write(&repo.objects)?;
    repo.set_genesis_authority(genesis)?;
    repo.set_current_authority(current)?;
    let head = if info.branches.contains_key("main") {
        Some("main".to_string())
    } else {
        info.branches.keys().next().cloned()
    };
    // The working tree first, then the index and the refs, as a branch
    // switch does: a checkout refused part way leaves no ref behind.
    if let Some(name) = &head {
        let tip = id_from("its head", &info.branches[name])?;
        let tree = Commit::from_signed(&repo.read_signed(tip)?)?.tree;
        repo.checkout_tree(tree, &dest)?;
        repo.write_index(&crate::repo_cmds::index_of_tree(&repo, tree)?)?;
    }
    let updates = refs
        .iter()
        .map(|(r, id)| crate::publish::update(r.clone(), None, Some(*id)))
        .collect();
    crate::publish::prepare(&repo, None, updates, None)?.apply(&repo)?;
    for (r, id) in &refs {
        repo.refs
            .write(&r.replacen("refs/", "refs/remote/origin/", 1), *id)?;
    }
    repo.refs.write_head(&Head::Branch(format!(
        "refs/branches/{}",
        head.as_deref().unwrap_or("main")
    )))?;
    unfinished.0 = None;
    eprintln!(
        "cloned {repo_id} from {url} into {}: {} branch(es), {} release(s), {} object(s), \
         all verified against its genesis",
        dest.display(),
        info.branches.len(),
        info.releases.len(),
        received.len()
    );
    Ok(())
}

pub fn fork(args: ForkArgs) -> Result<()> {
    let url = match args.from.clone() {
        Some(u) => u,
        None => active_instance()?,
    };
    let (label, sk) = load_secret(args.key.as_deref())?;
    let sk = std::sync::Arc::new(sk);
    let pk = sk.public();

    let repo_id = repo_id_arg(&args.repo_id)?;
    let dest_name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("fork-{}", &repo_id[..8]));
    let dest = std::env::current_dir()?.join(&dest_name);
    if dest.exists() {
        bail!("destination already exists: {:?}", dest);
    }

    // 1. Talk to the source instance.
    // Signed, so that a member can fork a private repository.
    let client = levcs_client::Client::new(url.clone()).with_reader(sk.clone());
    let info = published(&client, &url, &repo_id)?;

    // 2. Choose a source tip: prefer "main", else any branch.
    let (source_branch, source_tip_hex) = info
        .branches
        .iter()
        .find(|(k, _)| *k == "main")
        .or_else(|| info.branches.iter().next())
        .ok_or_else(|| anyhow!("source repo has no branches; nothing to fork"))?;
    let source_tip = id_from(&format!("branch {source_branch:?}"), source_tip_hex)?;

    // 3. Receive the source tip's history, and check it against the
    //    genesis the source's id pins (Rule R; see `receive`) before
    //    anything is written. It used to be written as sent.
    let source_ref = format!("refs/branches/{source_branch}");
    levcs_core::refs::validate_ref_name(&source_ref)?;
    let received = crate::receive::receive(
        &client,
        &repo_id,
        id_from("its genesis authority", &info.genesis_authority)?,
        id_from("its current authority", &info.current_authority)?,
        &[(source_ref, source_tip)],
        &[],
        None,
    )?;

    // 4. Initialise the destination repository with what was received.
    let repo = Repository::init_skeleton(&dest)?;
    received.write(&repo.objects)?;

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
            repo_id, source_branch, source_tip
        ),
    };
    let fork_signed = sign_commit(fork_commit, &sk)?;
    let fork_id = repo.write_signed(&fork_signed)?;

    // 10. Creating the repository sets its genesis and current authority,
    //     as `init` does. The fork commit is then its first publication,
    //     checked under Rule P before anything else is written, with the
    //     source history behind it checked under Rule H against the
    //     source's own genesis: it used to be signed over unverified. Then
    //     the working tree, then the branch and HEAD, so a checkout refused
    //     part way leaves no ref naming a tree that was never written.
    repo.set_genesis_authority(new_auth_id)?;
    repo.set_current_authority(new_auth_id)?;
    let main_ref = "refs/branches/main".to_string();
    let publish = crate::publish::prepare(
        &repo,
        Some(&pk),
        vec![crate::publish::update(
            main_ref.clone(),
            None,
            Some(fork_id),
        )],
        None,
    )?;
    repo.checkout_tree(source_commit.tree, &dest)?;
    publish.apply(&repo)?;
    repo.refs.write_head(&Head::Branch(main_ref.clone()))?;

    eprintln!(
        "forked {} into {:?}\n  new repo_id  = blake3:{}\n  fork commit  = {}\n  source tip   = {} ({})\n  source auth  = {}",
        repo_id,
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

/// `dial` is refused until it checks what it receives (Rule R). It wrote a
/// repository sent over a peer connection without verifying it against the
/// genesis its id pins, and nothing binds what the sender sends after the
/// handshake to the handshake (audit H3). The refusal comes before a key is
/// read, a connection opened or anything written. What follows it is kept,
/// and compiled, for when dial meets the rule.
fn dial_refused() -> Result<()> {
    bail!(
        "dial is refused until it checks what it receives: it would install a \
         repository sent over a peer connection without verifying it against the \
         genesis its id pins (doc/authority-semantics.md, Rule R). Clone the \
         repository from an instance instead: levcs clone <repo_id> --from <url>"
    )
}

pub fn dial(args: DialArgs) -> Result<()> {
    use std::net::TcpStream;

    dial_refused()?;

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
    // just received. The recipient never trusts the manifest's word for it,
    // and the genesis is pinned only once it verifies as one.
    let genesis_id = ObjectId::from_hex(&manifest.genesis_authority)
        .map_err(|_| anyhow!("manifest genesis_authority not a valid hash"))?;
    let genesis_signed = repo.read_signed(genesis_id)?;
    levcs_identity::verify::verify_genesis(&genesis_signed)
        .map_err(|e| anyhow!("received genesis authority: {e}"))?;
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
    // authority chain and the embedded signatures — refuse to record any
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

    // HEAD on main if present, otherwise any branch we got, otherwise a
    // release's predecessor: detached, since nothing here is a branch of
    // this replica's own (below). It used to name the release itself,
    // which is not a commit. The working tree is materialised first, so a
    // checkout refused part way leaves no ref naming a tree that was never
    // written.
    let tip = if let Some((_, hex)) = manifest
        .branches
        .iter()
        .find(|(k, _)| k.as_str() == "main")
        .or_else(|| manifest.branches.iter().next())
    {
        Some(ObjectId::from_hex(hex)?)
    } else if let Some((_, hex)) = manifest.releases.iter().next() {
        let id = ObjectId::from_hex(hex)?;
        Some(levcs_core::Release::from_signed(&repo.read_signed(id)?)?.predecessor)
    } else {
        None
    };
    if let Some(id) = tip {
        let commit = Commit::from_signed(&repo.read_signed(id)?)?;
        repo.checkout_tree(commit.tree, &dest)?;
    }

    // Record what was received, and publish none of it (Rule R.4, D6).
    // A v1 transfer carries no evidence that the sender published this
    // history, only the sender's word. So its refs are kept as records,
    // under refs/remote/origin/, not as this replica's branches, and the
    // sender's current authority is not adopted as this replica's: with
    // none, nothing here can be published. Accepting the history needs an
    // owner of the received authority to sign a bootstrap statement, and
    // that statement has no defined format yet (D6, deferred). Dial used to
    // install the refs as branches and set `current` from the manifest.
    repo.set_genesis_authority(genesis_id)?;
    for (name, hex) in &manifest.branches {
        let id = ObjectId::from_hex(hex)?;
        repo.refs
            .write(&format!("refs/remote/origin/branches/{name}"), id)?;
    }
    for (name, hex) in &manifest.releases {
        let id = ObjectId::from_hex(hex)?;
        repo.refs
            .write(&format!("refs/remote/origin/releases/{name}"), id)?;
    }
    if let Some(id) = tip {
        repo.refs.write_head(&Head::Detached(id))?;
    }

    eprintln!(
        "dial complete: repository at {:?}\n  repo_id    = blake3:{}\n  \
         received   = refs/remote/origin/ (the sender's current authority is {})\n\n\
         This replica can be read but not published from. Accepting received history \
         needs an owner's bootstrap statement, which has no defined format yet (D6, \
         deferred).",
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
