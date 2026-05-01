//! External-editor integration for the TUI's `e` key (§6.7).
//!
//! The editor flow is:
//!   1. Write the file's *current* bytes to a temp file in
//!      `std::env::temp_dir()`. The temp filename keeps the original
//!      extension so editors like vim pick the right syntax mode.
//!   2. Spawn the editor command, inheriting stdio so it has direct
//!      access to the controlling terminal. Block until exit.
//!   3. Read the temp file back. If the bytes are unchanged, the user
//!      either quit-without-saving or made a no-op edit — return
//!      `EditOutcome::Unchanged` so the caller keeps the previous
//!      resolution.
//!   4. Otherwise return `EditOutcome::Edited(new_bytes)`.
//!
//! Editor lookup precedence:
//!   1. `$LEVCS_REVIEW_EDITOR` — explicit override (also used in tests
//!      to inject a deterministic non-interactive editor).
//!   2. `$VISUAL`
//!   3. `$EDITOR`
//!   4. `vi` — POSIX-mandated fallback.
//!
//! The chosen value is split on ASCII whitespace, the first word is the
//! program and the rest are leading args. The temp-file path is appended
//! as the final argument. So `LEVCS_REVIEW_EDITOR='nano -w'` runs as
//! `nano -w /tmp/XXX`.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub enum EditOutcome {
    /// Editor exited with the buffer unchanged from what we wrote in.
    Unchanged,
    /// Editor saved a different buffer.
    Edited(Vec<u8>),
}

#[derive(Debug, thiserror::Error)]
pub enum EditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("editor exited non-zero: {0}")]
    EditorFailed(i32),

    #[error("could not resolve any editor (set $EDITOR or $VISUAL)")]
    NoEditor,

    #[error("editor command was empty")]
    EmptyCommand,
}

/// Resolve the editor command per the documented precedence. Pulled out
/// of `run_editor_on` so tests can verify selection logic without
/// spawning anything.
pub fn resolve_editor() -> Result<String, EditError> {
    for var in ["LEVCS_REVIEW_EDITOR", "VISUAL", "EDITOR"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                return Ok(v);
            }
        }
    }
    // Final fallback. Don't error out — a system without `vi` is rare,
    // and if `vi` isn't on PATH we'd rather surface an `EditorFailed`
    // than refuse to launch.
    Ok("vi".into())
}

/// Open the configured editor on `initial` and return whatever the
/// user saved. `path_hint` lets the caller preserve the original file
/// extension (so, e.g. vim picks Rust syntax mode for `.rs` files).
pub fn run_editor_on(initial: &[u8], path_hint: &Path) -> Result<EditOutcome, EditError> {
    let editor = resolve_editor()?;
    let mut parts = editor.split_whitespace();
    let prog = parts.next().ok_or(EditError::EmptyCommand)?;
    let leading: Vec<&str> = parts.collect();

    let tmp = make_tempfile(path_hint)?;
    std::fs::write(&tmp, initial)?;

    let status = Command::new(prog).args(&leading).arg(&tmp).status()?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(EditError::EditorFailed(status.code().unwrap_or(-1)));
    }

    let edited = std::fs::read(&tmp)?;
    let _ = std::fs::remove_file(&tmp);
    if edited == initial {
        Ok(EditOutcome::Unchanged)
    } else {
        Ok(EditOutcome::Edited(edited))
    }
}

/// Build a temp path whose suffix matches `hint` so editor syntax
/// detection works. Filename pattern: `levcs-review-<pid>-<ns>-<base>`.
fn make_tempfile(hint: &Path) -> std::io::Result<PathBuf> {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = hint
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("buffer");
    p.push(format!(
        "levcs-review-{}-{nanos}-{base}",
        std::process::id()
    ));
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Editor tests touch global process environment (env vars) and
    /// must run one at a time. `cargo test` runs tests in parallel by
    /// default; this Mutex serializes the editor-test critical section.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env_locked<F: FnOnce()>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Clear all three vars we care about before each test so we
        // never inherit a sibling test's leftover value.
        std::env::remove_var("LEVCS_REVIEW_EDITOR");
        std::env::remove_var("VISUAL");
        std::env::remove_var("EDITOR");
        f();
        std::env::remove_var("LEVCS_REVIEW_EDITOR");
        std::env::remove_var("VISUAL");
        std::env::remove_var("EDITOR");
    }

    #[test]
    fn resolve_editor_prefers_levcs_var() {
        with_env_locked(|| {
            std::env::set_var("LEVCS_REVIEW_EDITOR", "highest-priority");
            std::env::set_var("VISUAL", "second");
            std::env::set_var("EDITOR", "third");
            assert_eq!(resolve_editor().unwrap(), "highest-priority");
        });
    }

    #[test]
    fn resolve_editor_falls_back_to_visual_then_editor() {
        with_env_locked(|| {
            std::env::set_var("VISUAL", "vis");
            std::env::set_var("EDITOR", "edt");
            assert_eq!(resolve_editor().unwrap(), "vis");
        });
        with_env_locked(|| {
            std::env::set_var("EDITOR", "edt");
            assert_eq!(resolve_editor().unwrap(), "edt");
        });
        with_env_locked(|| {
            assert_eq!(resolve_editor().unwrap(), "vi");
        });
    }

    #[test]
    fn run_editor_captures_saved_bytes() {
        with_env_locked(|| {
            // Tiny shell script that overwrites $1 with "edited". Use a
            // unique, time-based filename so multiple test runs don't
            // collide on disk.
            let dir = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let script = dir.join(format!(
                "levcs-fake-editor-{}-{nanos}.sh",
                std::process::id()
            ));
            std::fs::write(&script, "#!/bin/sh\nprintf 'edited' > \"$1\"\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&script).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&script, perms).unwrap();
            }
            std::env::set_var("LEVCS_REVIEW_EDITOR", script.to_str().unwrap());

            let out = run_editor_on(b"original", Path::new("a.txt")).unwrap();
            match out {
                EditOutcome::Edited(bytes) => assert_eq!(bytes, b"edited"),
                other => panic!("expected Edited, got {other:?}"),
            }
            let _ = std::fs::remove_file(&script);
        });
    }

    #[test]
    fn run_editor_reports_unchanged_when_bytes_identical() {
        with_env_locked(|| {
            // `true`-as-editor leaves the temp file alone — a stand-in
            // for "user opens vim then quits without modifying anything".
            std::env::set_var("LEVCS_REVIEW_EDITOR", "true");
            let out = run_editor_on(b"unchanged", Path::new("x.txt")).unwrap();
            assert!(matches!(out, EditOutcome::Unchanged));
        });
    }

    #[test]
    fn run_editor_surfaces_failure_exit_code() {
        with_env_locked(|| {
            std::env::set_var("LEVCS_REVIEW_EDITOR", "false");
            match run_editor_on(b"x", Path::new("y")) {
                Err(EditError::EditorFailed(code)) => assert_ne!(code, 0),
                other => panic!("expected EditorFailed, got {other:?}"),
            }
        });
    }
}
