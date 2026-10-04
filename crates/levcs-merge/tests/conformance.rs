//! Conformance corpus runner (§8.2).
//!
//! Walks `tests/corpus/` and runs every scenario through the default
//! cascade engine. Each scenario lives in its own directory:
//!
//! ```text
//! tests/corpus/<NNN-scenario-name>/
//!   manifest.toml      # what to assert about the merge result
//!   base.<ext>         # base / common ancestor input
//!   ours.<ext>         # left side input
//!   theirs.<ext>       # right side input
//!   expected.<ext>     # (optional) exact expected merged output
//! ```
//!
//! The corpus is the canonical conformance fixture. Any independent
//! implementation of LeVCS that produces the same outcome on every
//! scenario here is conformant per §8.2; in particular every scenario
//! tagged `git_false_conflict = true` is a case where naive Git
//! produces a spurious conflict and LeVCS MUST resolve correctly.
//!
//! The runner deliberately does no expensive setup — it is one
//! integration test that iterates the corpus, so adding a scenario
//! does not change the binary count or build graph.

use std::path::{Path, PathBuf};

use levcs_merge::engine::{CascadeEngine, MergeConfig, MergeRule};
use levcs_merge::handler::MergeStatus;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    /// Human-readable summary of what this scenario tests. Required.
    description: String,
    /// Logical path used for handler routing — only the extension and
    /// basename matter (the engine doesn't read from disk for this).
    path: String,
    /// File extension used to find base/ours/theirs files. Defaults to
    /// the extension of `path`.
    #[serde(default)]
    input_ext: Option<String>,
    /// True iff naive Git would produce a false conflict on this
    /// scenario. Only used to compute corpus statistics; not asserted.
    #[serde(default)]
    git_false_conflict: bool,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    /// "merged" or "conflict". (NotApplicable is never a final cascade
    /// outcome — the engine always falls through to textual.)
    status: String,
    /// Required handler name (e.g., "json", "tree-sitter:rust",
    /// "textual"). Asserts the cascade routed correctly.
    handler: String,
    /// Substrings every one of which must appear in the merged output.
    /// Useful when ordering is implementation-defined (object key
    /// ordering, etc.) but specific content must be present.
    #[serde(default)]
    contains: Vec<String>,
    /// Substrings none of which may appear. Used to check that
    /// drop-and-modify resolutions actually drop, or that conflict
    /// markers are absent on a merged outcome.
    #[serde(default)]
    not_contains: Vec<String>,
    /// If present, the merged output must equal this file's bytes
    /// exactly. (`expected.<ext>` next to base/ours/theirs.)
    #[serde(default)]
    content_file: Option<String>,
    /// Conflict-only: the number of conflict regions. None means "any
    /// nonzero count".
    #[serde(default)]
    conflict_count: Option<usize>,
    /// Conflict-only: each region's description must contain at least
    /// one of these substrings. Used to assert that the cascade landed
    /// on the expected diagnosis (e.g., "modify-vs-delete", "concurrent
    /// edits").
    #[serde(default)]
    region_descriptions_contain: Vec<String>,
    /// Merged-only: any of these notes' messages must contain at least
    /// one of these substrings. Used to assert that, e.g., recursive
    /// descent fired.
    #[serde(default)]
    notes_contain: Vec<String>,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn collect_scenarios() -> Vec<PathBuf> {
    let root = corpus_root();
    assert!(
        root.is_dir(),
        "corpus directory missing: {}",
        root.display()
    );
    let mut out = Vec::new();
    for ent in std::fs::read_dir(&root).expect("read corpus dir").flatten() {
        let p = ent.path();
        if !p.is_dir() {
            continue;
        }
        if p.join("manifest.toml").is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn run_scenario(dir: &Path) -> Result<(), String> {
    let manifest_text = std::fs::read_to_string(dir.join("manifest.toml"))
        .map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Manifest =
        toml::from_str(&manifest_text).map_err(|e| format!("parse manifest: {e}"))?;
    let ext = manifest
        .input_ext
        .clone()
        .or_else(|| {
            Path::new(&manifest.path)
                .extension()
                .and_then(|e| e.to_str().map(String::from))
        })
        .ok_or_else(|| "manifest.path has no extension and input_ext is unset".to_string())?;

    let base = std::fs::read(dir.join(format!("base.{ext}")))
        .map_err(|e| format!("read base.{ext}: {e}"))?;
    let ours = std::fs::read(dir.join(format!("ours.{ext}")))
        .map_err(|e| format!("read ours.{ext}: {e}"))?;
    let theirs = std::fs::read(dir.join(format!("theirs.{ext}")))
        .map_err(|e| format!("read theirs.{ext}: {e}"))?;

    // The structural handlers run only where the repository's merge.toml
    // selects them, so each scenario selects the handler it documents for
    // its own path. `default_engine_merges_every_scenario_textually` covers
    // what happens without that rule.
    let engine = CascadeEngine::default().with_config(MergeConfig {
        schema_version: 1,
        rules: vec![MergeRule {
            glob: manifest.path.clone(),
            handler: manifest.expected.handler.clone(),
        }],
        plugins: vec![],
        policy: None,
    });
    let result = engine.merge_file(Path::new(&manifest.path), &base, &ours, &theirs);

    if result.handler != manifest.expected.handler {
        return Err(format!(
            "[{}] expected handler {:?}, got {:?}",
            manifest.description, manifest.expected.handler, result.handler
        ));
    }

    match (manifest.expected.status.as_str(), &result.status) {
        ("merged", MergeStatus::Merged { content, notes }) => {
            let s = String::from_utf8_lossy(content);
            for needle in &manifest.expected.contains {
                if !s.contains(needle) {
                    return Err(format!(
                        "[{}] merged content missing substring {:?}\n--- output ---\n{s}\n",
                        manifest.description, needle
                    ));
                }
            }
            for needle in &manifest.expected.not_contains {
                if s.contains(needle) {
                    return Err(format!(
                        "[{}] merged content unexpectedly contains {:?}\n--- output ---\n{s}\n",
                        manifest.description, needle
                    ));
                }
            }
            if let Some(content_file) = &manifest.expected.content_file {
                let want = std::fs::read(dir.join(content_file))
                    .map_err(|e| format!("read {content_file}: {e}"))?;
                if want != *content {
                    return Err(format!(
                        "[{}] merged content does not match {content_file}\n--- want ---\n{}\n--- got ---\n{s}\n",
                        manifest.description,
                        String::from_utf8_lossy(&want)
                    ));
                }
            }
            for needle in &manifest.expected.notes_contain {
                if !notes.iter().any(|n| n.message.contains(needle)) {
                    let messages: Vec<&str> = notes.iter().map(|n| n.message.as_str()).collect();
                    return Err(format!(
                        "[{}] expected a note containing {:?}, saw {:?}",
                        manifest.description, needle, messages
                    ));
                }
            }
            // Sanity check: a merged outcome must not carry conflict markers.
            // A handler that wrote markers but reported Merged would silently
            // smuggle conflicts past CI.
            if s.contains("<<<<<<< ours") || s.contains("=======") || s.contains(">>>>>>> theirs") {
                return Err(format!(
                    "[{}] merged outcome contains conflict markers — handler {:?} is buggy\n--- output ---\n{s}\n",
                    manifest.description, result.handler
                ));
            }
            Ok(())
        }
        ("conflict", MergeStatus::Conflict { regions, .. }) => {
            if let Some(want) = manifest.expected.conflict_count {
                if regions.len() != want {
                    return Err(format!(
                        "[{}] expected {} conflict region(s), got {}",
                        manifest.description,
                        want,
                        regions.len()
                    ));
                }
            } else if regions.is_empty() {
                return Err(format!(
                    "[{}] expected at least one conflict region, got zero",
                    manifest.description
                ));
            }
            for needle in &manifest.expected.region_descriptions_contain {
                if !regions.iter().any(|r| r.description.contains(needle)) {
                    let descs: Vec<&str> = regions.iter().map(|r| r.description.as_str()).collect();
                    return Err(format!(
                        "[{}] expected a region with description containing {:?}, saw {:?}",
                        manifest.description, needle, descs
                    ));
                }
            }
            Ok(())
        }
        (want, got) => Err(format!(
            "[{}] expected status {want:?}, got {got:?}",
            manifest.description
        )),
    }
}

#[test]
fn corpus_is_non_empty() {
    let scenarios = collect_scenarios();
    assert!(
        scenarios.len() >= 10,
        "conformance corpus is too thin: {} scenario(s) found at {}",
        scenarios.len(),
        corpus_root().display()
    );
}

#[test]
fn corpus_runs_clean() {
    let scenarios = collect_scenarios();
    let mut failures: Vec<String> = Vec::new();
    let mut git_false_conflict_count = 0usize;
    for dir in &scenarios {
        // Re-read the manifest so we can count git-false-conflict
        // scenarios separately for the summary line below.
        if let Ok(t) = std::fs::read_to_string(dir.join("manifest.toml")) {
            if let Ok(m) = toml::from_str::<Manifest>(&t) {
                if m.git_false_conflict {
                    git_false_conflict_count += 1;
                }
            }
        }
        if let Err(e) = run_scenario(dir) {
            failures.push(format!("\n  in {}:\n    {e}", dir.display()));
        }
    }
    eprintln!(
        "conformance: {} scenario(s) total, {} flagged as git-false-conflict",
        scenarios.len(),
        git_false_conflict_count
    );
    assert!(
        failures.is_empty(),
        "conformance failures:{}",
        failures.join("")
    );
}

/// Without a rule, no scenario reaches a structural handler: every one is
/// merged by `textual`. The git-false-conflict scenarios then conflict as
/// git would; that is the cost of not trusting the structural handlers
/// until a validator can confirm their output.
#[test]
fn default_engine_merges_every_scenario_textually() {
    for dir in collect_scenarios() {
        let manifest: Manifest =
            toml::from_str(&std::fs::read_to_string(dir.join("manifest.toml")).unwrap()).unwrap();
        let ext = manifest
            .input_ext
            .clone()
            .or_else(|| {
                Path::new(&manifest.path)
                    .extension()
                    .and_then(|e| e.to_str().map(String::from))
            })
            .unwrap();
        let read = |side: &str| std::fs::read(dir.join(format!("{side}.{ext}"))).unwrap();
        let result = CascadeEngine::default().merge_file(
            Path::new(&manifest.path),
            &read("base"),
            &read("ours"),
            &read("theirs"),
        );
        assert!(
            result.handler == "textual" || result.handler == "none",
            "{}: default engine used {}",
            dir.display(),
            result.handler
        );
    }
}
