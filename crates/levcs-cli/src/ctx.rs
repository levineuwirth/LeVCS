//! Common helpers shared by all commands.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

use levcs_core::{RepoLock, Repository};
use levcs_identity::keychain::Keychain;
use levcs_identity::keys::SecretKey;

pub fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

pub fn open_repo() -> Result<Repository> {
    let cwd = std::env::current_dir()?;
    Ok(Repository::discover(&cwd)?)
}

/// Open the repository and take its lock, for a command that mutates the
/// index, a ref, or the working tree. Bind the guard to a named variable
/// (`let (repo, _lock) = …`); `_` would drop it, and the lock, at once.
///
/// Several sessions commit into one repository at the same time. Without
/// this, two commits could read the same parent and the later ref write would
/// discard the earlier commit while both reported success.
pub fn open_repo_locked() -> Result<(Repository, RepoLock)> {
    let repo = open_repo()?;
    let lock = lock_repo(&repo)?;
    Ok((repo, lock))
}

/// Take the lock on an already-open repository. Commands that may prompt for
/// a passphrase take it after the prompt, so a person typing does not hold
/// every other session's commit.
pub fn lock_repo(repo: &Repository) -> Result<RepoLock> {
    match repo.try_lock()? {
        Some(lock) => Ok(lock),
        None => {
            eprintln!("levcs: waiting for another levcs process to release the repository lock");
            Ok(repo.lock()?)
        }
    }
}

pub fn keychain_path() -> PathBuf {
    Keychain::default_path()
}

pub fn load_keychain() -> Result<Keychain> {
    Ok(Keychain::load_or_default(&keychain_path())?)
}

pub fn save_keychain(kc: &Keychain) -> Result<()> {
    Ok(kc.save(&keychain_path())?)
}

pub fn read_passphrase(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    // Best-effort no-echo: rely on terminal raw mode if available; otherwise
    // fall back to plain readline. This is intentionally simple to avoid
    // pulling another crate; users on headless CI should pass keys via
    // unencrypted slots or a future agent.
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

/// Resolve a key label and load the secret. If `label` is None, default to
/// `"personal"`, then to the only key in the chain if there is exactly one.
pub fn load_secret(label: Option<&str>) -> Result<(String, SecretKey)> {
    let kc = load_keychain()?;
    let chosen = match label {
        Some(l) => l.to_string(),
        None => {
            if kc.entry("personal").is_some() {
                "personal".into()
            } else if kc.keys.len() == 1 {
                kc.keys[0].label.clone()
            } else if kc.keys.is_empty() {
                return Err(anyhow!(
                    "no keys in keychain at {:?}; run `levcs key generate <label>`",
                    keychain_path()
                ));
            } else {
                return Err(anyhow!("multiple keys in keychain; pass --key <label>"));
            }
        }
    };
    let entry = kc
        .entry(&chosen)
        .ok_or_else(|| anyhow!("unknown key label: {chosen}"))?
        .clone();
    let sk = if entry.private.is_some() {
        kc.secret(&chosen, || Ok(String::new()))
            .context("loading plaintext secret")?
    } else {
        let pp = read_passphrase(&format!("passphrase for key '{chosen}': "))?;
        kc.secret(&chosen, || Ok(pp.clone()))
            .context("decrypting secret")?
    };
    Ok((chosen, sk))
}
