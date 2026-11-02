//! `levcs --version` names the commit the binary was built from, so that
//! the build a machine runs can be told from another of the same version.

use std::path::Path;
use std::process::Command;

/// The build script, for its `describe`.
#[allow(dead_code)]
mod build_commit {
    include!("../../../scripts/build-commit.rs");
}

#[test]
fn version_names_the_commit() {
    let out = Command::new(env!("CARGO_BIN_EXE_levcs"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("levcs {}\n", env!("LEVCS_VERSION"))
    );
}

/// What the build recorded is what the checkout says now, so the build
/// script ran again for every change that alters it. Not when the build
/// was told what to report.
#[test]
fn the_commit_is_the_checkouts() {
    if env!("LEVCS_BUILD_COMMIT_GIVEN") == "true" {
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let now = build_commit::describe(&root).unwrap_or_else(|| "unknown".into());
    assert_eq!(env!("LEVCS_BUILD_COMMIT"), now);
}

/// A source is what a binary is compiled from, the build script included,
/// and not tests, fixtures or documentation, wherever they are.
#[test]
fn a_source_is_what_a_binary_is_compiled_from() {
    let root = std::env::temp_dir().join(format!("levcs-build-commit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let files = [
        ("Cargo.toml", true),
        ("Cargo.lock", true),
        ("scripts/build-commit.rs", true),
        ("crates/a/Cargo.toml", true),
        ("crates/a/build.rs", true),
        ("crates/a/src/lib.rs", true),
        ("crates/a/src/bin/tool.rs", true),
        ("crates/a/tests/t.rs", false),
        ("crates/a/tests/fixtures/src/lib.rs", false),
        ("crates/a/benches/b.rs", false),
        ("crates/a/README.md", false),
        ("scripts/bench.sh", false),
        ("deploy/README.md", false),
        ("deploy/instance.toml.example", false),
        ("README.md", false),
    ];
    for (path, _) in files {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "one\n").unwrap();
    }
    let git = |args: &[&str]| -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["-c", "user.name=test", "-c", "user.email=test@invalid"])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8(out.stdout)
            .unwrap()
            .trim_end()
            .to_string()
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "one"]);
    let clean = format!("git {}", git(&["rev-parse", "HEAD"]));
    let modified = format!("{clean} modified");
    let describe = || build_commit::describe(&root);
    assert_eq!(describe(), Some(clean.clone()));

    for (path, source) in files {
        std::fs::write(root.join(path), "two\n").unwrap();
        let want = if source { &modified } else { &clean };
        assert_eq!(describe().as_ref(), Some(want), "{path} edited");
        git(&["add", "--", path]);
        assert_eq!(describe().as_ref(), Some(want), "{path} staged");
        git(&["reset", "-q", "--", path]);
        std::fs::remove_file(root.join(path)).unwrap();
        assert_eq!(describe().as_ref(), Some(want), "{path} deleted");
        git(&["checkout", "-q", "--", path]);
        assert_eq!(describe(), Some(clean.clone()), "{path} restored");
    }
    // A file not yet tracked reaches a binary only through a tracked source
    // that names it, which is then modified.
    std::fs::write(root.join("crates/a/src/new.rs"), "new\n").unwrap();
    assert_eq!(describe(), Some(clean.clone()));

    // A tree inside a checkout but not at its top is not that checkout's.
    assert_eq!(build_commit::describe(&root.join("crates/a")), None);
    std::fs::remove_dir_all(root.join(".git")).unwrap();
    assert_eq!(describe(), None);
    let _ = std::fs::remove_dir_all(&root);
}
