// The build script of each binary that says what it was built from
// (`levcs`, `levcs-instance`), compiled into each by `include!`. The tests
// in levcs-cli's tests/version.rs include it too, to test `describe`.
//
// It sets these variables for the crate's code:
//
// - `LEVCS_BUILD_COMMIT`: `git <id>` for a build from a clean checkout of
//   this repository, `git <id> modified` when a source differs from that
//   commit, and `unknown` outside a checkout (a source export, or a LeVCS
//   clone of the repository). The environment variable of the same name,
//   if set, is taken as it is instead, for a build whose source the
//   checkout cannot vouch for.
// - `LEVCS_BUILD_COMMIT_GIVEN`: `true` when it was taken from that
//   variable, so that a test knows not to compare it with the checkout.
//   (Cargo also sets these variables when it runs a test, so a test cannot
//   ask the environment.)
// - `LEVCS_VERSION`: the package version followed by that, in parentheses.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A source is what the binaries are compiled from: these, relative to the
/// workspace root, and in each crate the files in `CRATE_SOURCES`. Tests,
/// benches, fixtures and documentation are not, wherever they are, so a
/// change to them neither marks a build modified nor runs this script
/// again. A file outside these that a binary includes must be added here.
const WORKSPACE_SOURCES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".cargo",
    "scripts/build-commit.rs",
];

/// The sources in each crate under `crates/`.
const CRATE_SOURCES: &[&str] = &["Cargo.toml", "build.rs", "src"];

fn main() {
    println!("cargo:rerun-if-env-changed=LEVCS_BUILD_COMMIT");
    let (commit, given) = match std::env::var("LEVCS_BUILD_COMMIT") {
        Ok(given) if !given.trim().is_empty() => {
            let given = given.trim().to_string();
            assert!(
                !given.chars().any(char::is_control),
                "LEVCS_BUILD_COMMIT must be one line of text"
            );
            (given, true)
        }
        _ => {
            let root = workspace_root();
            let commit = root.as_deref().and_then(describe);
            if let (Some(root), Some(_)) = (&root, &commit) {
                for path in watched(root) {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
            (commit.unwrap_or_else(|| "unknown".into()), false)
        }
    };
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    println!("cargo:rustc-env=LEVCS_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=LEVCS_BUILD_COMMIT_GIVEN={given}");
    if commit == "unknown" {
        println!("cargo:rustc-env=LEVCS_VERSION={version} (unknown commit)");
    } else {
        println!("cargo:rustc-env=LEVCS_VERSION={version} ({commit})");
    }
}

/// The workspace the crate being built is in: two levels above its manifest.
fn workspace_root() -> Option<PathBuf> {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    manifest.parent()?.parent()?.canonicalize().ok()
}

/// Git's output, without its last newline, or `None` if it failed. Read
/// only: a status that refreshed the index would change a file this script
/// watches, and so run it again on every build.
fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("--no-optional-locks")
        .args(args)
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    out.status
        .success()
        .then(|| text.trim_end_matches('\n').to_string())
}

/// `git <id>` for the commit the workspace at `root` is checked out at,
/// followed by ` modified` when a source differs from it. `None` when `root`
/// is not the top of a git checkout with a commit, or git cannot say.
pub(crate) fn describe(root: &Path) -> Option<String> {
    let root = root.canonicalize().ok()?;
    // A source tree unpacked inside some other checkout is not that
    // checkout's commit.
    let top = git(&root, &["rev-parse", "--show-toplevel"])?;
    if Path::new(&top).canonicalize().ok()? != root {
        return None;
    }
    let head = git(&root, &["rev-parse", "--verify", "--quiet", "HEAD"])?;
    let mut status: Vec<String> = ["status", "--porcelain", "--untracked-files=no", "--"]
        .map(String::from)
        .into();
    status.extend(WORKSPACE_SOURCES.iter().map(|p| p.to_string()));
    // `*` in a glob pathspec stays within one directory, so a `src` under a
    // crate's tests is not a source.
    for name in CRATE_SOURCES {
        status.push(format!(":(glob)crates/*/{name}"));
        status.push(format!(":(glob)crates/*/{name}/**"));
    }
    let status: Vec<&str> = status.iter().map(String::as_str).collect();
    let changed = git(&root, &status)?;
    Some(if changed.is_empty() {
        format!("git {head}")
    } else {
        format!("git {head} modified")
    })
}

/// What should run this script again when it changes: HEAD, its branch and
/// the index, which move on a checkout, a commit or a reset, and the
/// sources. A path that does not exist is left out, since Cargo runs a
/// script again on every build for a watched path that is missing.
fn watched(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut refs = vec!["HEAD".to_string(), "index".into(), "packed-refs".into()];
    refs.extend(git(root, &["symbolic-ref", "--quiet", "HEAD"]));
    for name in &refs {
        paths.extend(git(root, &["rev-parse", "--git-path", name]).map(|p| root.join(p)));
    }
    paths.extend(WORKSPACE_SOURCES.iter().map(|p| root.join(p)));
    if let Ok(crates) = std::fs::read_dir(root.join("crates")) {
        for krate in crates.flatten() {
            paths.extend(CRATE_SOURCES.iter().map(|name| krate.path().join(name)));
        }
    }
    paths.retain(|p| p.exists());
    paths
}
