//! Which key signs. A keychain shared by more than one hand (an owner and
//! an agent contributor, in the vaults) must never have the owner's key
//! chosen for a command that did not name it: the signature is the record
//! of whose hand made the change.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn levcs(work: &Path, cfg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_levcs"))
        .current_dir(work)
        .env("XDG_CONFIG_HOME", cfg)
        .args(args)
        .output()
        .unwrap()
}

fn ok(work: &Path, cfg: &Path, args: &[&str]) -> String {
    let o = levcs(work, cfg, args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// An owner key labelled `personal` (what `init` creates when not told
/// otherwise) and an `agent` contributor, in one keychain.
fn setup(tag: &str) -> (PathBuf, PathBuf, String) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("levcs-keysel-{tag}-{}-{stamp}", std::process::id()));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    ok(&work, &cfg, &["init", "--key", "personal"]);
    ok(&work, &cfg, &["key", "generate", "agent"]);
    let agent = ok(&work, &cfg, &["key", "show", "agent"])
        .trim()
        .to_string();
    ok(
        &work,
        &cfg,
        &[
            "authority",
            "add",
            &agent,
            "--role",
            "contributor",
            "--signing-key",
            "personal",
        ],
    );
    (work, cfg, agent)
}

#[test]
fn an_authority_change_without_a_signing_key_is_refused_and_changes_nothing() {
    let (work, cfg, agent) = setup("promote");
    let authority = ok(&work, &cfg, &["authority", "show"]);
    let log = ok(&work, &cfg, &["log"]);

    // The audit's case: this used to sign with the sole owner's key.
    let o = levcs(
        &work,
        &cfg,
        &["authority", "promote", &agent, "--role", "owner"],
    );
    assert!(
        !o.status.success(),
        "promote without --signing-key succeeded: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("--signing-key"));

    ok(&work, &cfg, &["key", "generate", "third"]);
    let third = ok(&work, &cfg, &["key", "show", "third"])
        .trim()
        .to_string();
    let o = levcs(
        &work,
        &cfg,
        &["authority", "add", &third, "--role", "reader"],
    );
    assert!(!o.status.success(), "add without --signing-key succeeded");
    let o = levcs(&work, &cfg, &["authority", "remove", &agent]);
    assert!(
        !o.status.success(),
        "remove without --signing-key succeeded"
    );

    assert_eq!(ok(&work, &cfg, &["authority", "show"]), authority);
    assert_eq!(
        ok(&work, &cfg, &["log"]),
        log,
        "a refused change made a commit"
    );
}

#[test]
fn several_keys_mean_the_signing_key_is_named() {
    let (work, cfg, agent) = setup("commit");
    std::fs::write(work.join("note.md"), b"note\n").unwrap();
    ok(&work, &cfg, &["track", "note.md"]);
    let log = ok(&work, &cfg, &["log"]);

    // `personal` used to be chosen whenever it existed.
    let o = levcs(&work, &cfg, &["commit", "-m", "unnamed"]);
    assert!(
        !o.status.success(),
        "a commit chose a key among several: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("--key"));
    assert_eq!(
        ok(&work, &cfg, &["log"]),
        log,
        "the refused commit moved HEAD"
    );

    ok(&work, &cfg, &["commit", "-m", "named", "--key", "agent"]);
    let log = ok(&work, &cfg, &["log"]);
    let first = log.lines().find(|l| l.starts_with("Author:")).unwrap();
    assert!(
        first.contains(agent.trim_start_matches("ed25519:")),
        "the named key did not sign: {first}"
    );
}

#[test]
fn a_single_key_still_signs_without_being_named() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("levcs-keysel-solo-{}-{stamp}", std::process::id()));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    ok(&work, &cfg, &["init", "--key", "solo"]);
    std::fs::write(work.join("a.md"), b"a\n").unwrap();
    ok(&work, &cfg, &["track", "a.md"]);
    ok(&work, &cfg, &["commit", "-m", "solo"]);
}

#[test]
fn init_with_several_keys_names_the_owner() {
    // `init` used to default to `personal` whenever it existed, so with an
    // owner's `personal` and an agent's key present, a repository an agent
    // created was owned by the owner's key.
    let (work, cfg, agent) = setup("init");
    let fresh = work.parent().unwrap().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    let o = levcs(&fresh, &cfg, &["init"]);
    assert!(
        !o.status.success(),
        "init chose a key among several: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("--key"));
    assert!(
        !fresh.join(".levcs").exists(),
        "a refused init left a repository"
    );

    ok(&fresh, &cfg, &["init", "--key", "agent"]);
    let authority = ok(&fresh, &cfg, &["authority", "show"]);
    assert!(
        authority.contains(&agent) && authority.matches("[[member]]").count() == 1,
        "the named key is not the sole genesis owner:\n{authority}"
    );
}
