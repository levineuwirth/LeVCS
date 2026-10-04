//! Identity-side commands: `levcs key ...` and `levcs authority ...`.

use std::fs;

use anyhow::{anyhow, bail, Context, Result};

use levcs_core::{Commit, CommitFlags, ZERO_ID};
use levcs_identity::authority::{AuthorityBody, MemberEntry, Role};
use levcs_identity::keychain::Keychain;
use levcs_identity::keys::{PublicKey, SecretKey};
use levcs_identity::sign::{sign_authority, sign_commit};

use crate::cli::*;
use crate::ctx::{
    load_keychain, load_secret, now_micros, open_repo, read_passphrase, save_keychain,
};

pub fn key(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::Generate { label, encrypt } => {
            let mut kc = load_keychain()?;
            if kc.entry(&label).is_some() {
                bail!("key already exists: {label}");
            }
            let sk = SecretKey::generate();
            if encrypt {
                let pp = read_passphrase("new passphrase: ")?;
                let pp2 = read_passphrase("confirm passphrase: ")?;
                if pp != pp2 {
                    bail!("passphrases do not match");
                }
                kc.add_encrypted(&label, &sk, pp.as_bytes())?;
            } else {
                kc.add_plaintext(&label, &sk)?;
            }
            save_keychain(&kc)?;
            println!("generated key '{}'\n  public: {}", label, sk.public());
            Ok(())
        }
        KeyCmd::List => {
            let kc = load_keychain()?;
            for e in &kc.keys {
                let kind = if e.private_encrypted.is_some() {
                    "encrypted"
                } else {
                    "plaintext"
                };
                println!("{}\t{}\t{kind}", e.label, e.public);
            }
            Ok(())
        }
        KeyCmd::Show { label } => {
            let kc = load_keychain()?;
            let e = kc
                .entry(&label)
                .ok_or_else(|| anyhow!("no such key: {label}"))?;
            println!("{}", e.public);
            Ok(())
        }
        KeyCmd::Export { label, path } => {
            let kc = load_keychain()?;
            let e = kc
                .entry(&label)
                .ok_or_else(|| anyhow!("no such key: {label}"))?
                .clone();
            let mut single = Keychain::new();
            single.keys.push(e);
            single.save(&path)?;
            eprintln!("exported '{label}' to {:?}", path);
            Ok(())
        }
        KeyCmd::Import { label, path } => {
            let mut kc = load_keychain()?;
            let imported = Keychain::load_or_default(&path).context("loading import file")?;
            let entry = imported
                .keys
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("import file has no keys"))?;
            let mut entry = entry;
            entry.label = label;
            if kc.entry(&entry.label).is_some() {
                bail!("key already exists: {}", entry.label);
            }
            kc.keys.push(entry);
            save_keychain(&kc)?;
            Ok(())
        }
        KeyCmd::Remove { label } => {
            let mut kc = load_keychain()?;
            kc.remove(&label)?;
            save_keychain(&kc)?;
            eprintln!("removed key '{label}'");
            Ok(())
        }
        KeyCmd::Rename { old, new } => {
            let mut kc = load_keychain()?;
            kc.rename(&old, &new)?;
            save_keychain(&kc)?;
            Ok(())
        }
    }
}

pub fn authority(cmd: AuthorityCmd) -> Result<()> {
    let repo = open_repo()?;
    let auth_id = repo
        .current_authority()?
        .ok_or_else(|| anyhow!("no current authority"))?;
    let signed = repo.read_signed(auth_id)?;
    let body = AuthorityBody::parse(&signed.body)?;

    match cmd {
        AuthorityCmd::Show => {
            let toml_text = levcs_identity::authority::render_toml_authority(&body)?;
            println!("{toml_text}");
            Ok(())
        }
        AuthorityCmd::List => {
            for m in &body.members {
                println!("{}\t{}\t{}", m.role.name(), m.handle, m.key);
            }
            Ok(())
        }
        AuthorityCmd::Add {
            key,
            role,
            handle,
            signing_key,
        } => {
            let pk = PublicKey::parse_levcs(&key)?;
            let role = Role::from_name(&role)?;
            let handle = handle.unwrap_or_default();
            mutate_authority(signing_key.as_deref(), |new_body, signer_pk| {
                if new_body.find_member(&pk).is_some() {
                    bail!("member already exists: {pk}");
                }
                new_body.members.push(MemberEntry {
                    key: pk,
                    handle: handle.clone(),
                    role,
                    added_micros: now_micros(),
                    added_by: signer_pk,
                });
                Ok(())
            })
        }
        AuthorityCmd::Remove { key, signing_key } => {
            let pk = PublicKey::parse_levcs(&key)?;
            mutate_authority(signing_key.as_deref(), |new_body, _| {
                let before = new_body.members.len();
                new_body.members.retain(|m| m.key != pk);
                if new_body.members.len() == before {
                    bail!("no such member: {pk}");
                }
                Ok(())
            })
        }
        AuthorityCmd::Promote {
            key,
            role,
            signing_key,
        } => {
            let pk = PublicKey::parse_levcs(&key)?;
            let role = Role::from_name(&role)?;
            mutate_authority(signing_key.as_deref(), |new_body, _| {
                let m = new_body
                    .members
                    .iter_mut()
                    .find(|m| m.key == pk)
                    .ok_or_else(|| anyhow!("no such member: {pk}"))?;
                m.role = role;
                Ok(())
            })
        }
    }
}

/// Run `f` against a clone of the current authority's body, then create a
/// successor authority and an authority-modifying commit on the current
/// branch. The signing key must hold owner role.
fn mutate_authority<F>(signing_key_label: Option<&str>, mut f: F) -> Result<()>
where
    F: FnMut(&mut AuthorityBody, PublicKey) -> Result<()>,
{
    let repo = open_repo()?;
    // The owner's key is never chosen for the caller. This used to look up
    // the sole owner and sign with whichever keychain key matched, so any
    // process able to run `levcs` could change membership as the owner
    // without naming that key: `authority promote <agent> --role owner`
    // produced a commit authored by the owner's key with no prompt.
    let Some(label) = signing_key_label else {
        bail!(
            "authority changes are signed with an owner's key; name it with \
             --signing-key <label>"
        );
    };
    let (_, sk) = load_secret(Some(label))?;
    let pk = sk.public();
    // Locked after the key is loaded, so a passphrase prompt never holds
    // the repository; the authority is re-read under the lock below.
    let _lock = crate::ctx::lock_repo(&repo)?;
    let cur_id = repo
        .current_authority()?
        .ok_or_else(|| anyhow!("no current authority"))?;
    let cur_signed = repo.read_signed(cur_id)?;
    let cur_body = AuthorityBody::parse(&cur_signed.body)?;
    let me = cur_body
        .find_member(&pk)
        .ok_or_else(|| anyhow!("your key is not in the current authority"))?;
    if me.role < Role::Owner {
        bail!("authority modifications require owner role");
    }
    // Build successor body.
    let mut new_body = cur_body.clone();
    new_body.previous_authority = cur_id;
    new_body.version = cur_body
        .version
        .checked_add(1)
        .ok_or_else(|| anyhow!("version overflow"))?;
    new_body.created_micros = now_micros();
    f(&mut new_body, pk)?;
    new_body.normalize()?;
    let new_signed = sign_authority(&new_body, &sk)?;
    let new_auth_id = repo.write_signed(&new_signed)?;

    // Build a commit whose tree contains `.levcs/authority` pointing at the
    // new authority object. The tree mirrors HEAD's tree, plus this entry.
    let head = repo.refs.resolve_head()?;
    let parents = head.map(|p| vec![p]).unwrap_or_default();
    let parent_tree_id = if let Some(h) = head {
        Commit::from_signed(&repo.read_signed(h)?)?.tree
    } else {
        ZERO_ID
    };
    let new_tree_id =
        crate::tree_helpers::put_authority_in_tree(&repo, parent_tree_id, new_auth_id)?;
    let commit_obj = Commit {
        tree: new_tree_id,
        parents,
        authority: cur_id,
        author_key: pk.0,
        timestamp_micros: now_micros(),
        flags: CommitFlags::MODIFIES_AUTHORITY,
        message: "modify authority".into(),
    };
    let signed_commit = sign_commit(commit_obj, &sk)?;
    let id = repo.write_signed(&signed_commit)?;
    if let Some(branch) = repo.current_branch()? {
        repo.refs.compare_and_write(&branch, head, id)?;
    }
    repo.set_current_authority(new_auth_id)?;
    eprintln!("authority updated to {new_auth_id} (commit {id})");
    Ok(())
}

#[allow(dead_code)]
fn _io_unused(_: fs::Metadata) {}
