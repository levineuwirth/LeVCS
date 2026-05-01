//! Cascade engine. Selects a handler by configured glob rule (with built-in
//! defaults), and falls through on `NotApplicable`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use glob::Pattern;
use serde::{Deserialize, Serialize};

use crate::format::{JsonHandler, TomlHandler};
use crate::format_extra::{MarkdownHandler, ProseHandler, XmlHandler, YamlHandler};
use crate::handler::{MergeHandler, MergeResult, MergeStatus};
use crate::plugin::{PluginConfig, PluginHandler};
use crate::textual::TextualHandler;
use crate::tree_sitter_handler::{Lang, TreeSitterHandler};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MergeConfig {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default, rename = "rule")]
    pub rules: Vec<MergeRule>,
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<MergePluginEntry>,
    #[serde(default)]
    pub policy: Option<MergePolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergeRule {
    pub glob: String,
    pub handler: String,
}

/// A `[[plugin]]` entry in `.levcs/merge.toml` (§6.6.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergePluginEntry {
    pub name: String,
    /// URL or local path the plugin can be fetched from. Not consulted by
    /// the engine itself — callers fetch the bytes and pass them in.
    #[serde(default)]
    pub source: String,
    /// Hex-encoded BLAKE3 of the WASM module. May appear with or without the
    /// `blake3:` prefix in the TOML; both are accepted.
    pub hash: String,
}

/// `policy.allowed_handlers` from §6.6.2 — the repository's view of which
/// handler names may legally appear in merge metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MergePolicy {
    #[serde(default)]
    pub allowed_handlers: Vec<String>,
}

/// Handler-aggressiveness rank used by §6.6.3 to enforce the
/// "per-user config can demote, never promote" rule. The four tiers
/// match the spec's ordering exactly:
///
///   * `0` — textual fallback (least aggressive)
///   * `1` — format-aware (json, yaml, toml, xml, markdown, prose)
///   * `2` — tree-sitter:* built-ins
///   * `3` — anything else (assumed to be a plugin)
///
/// Unknown handler names are treated as plugins (rank 3) so an
/// unknown-named override always counts as a *promotion* attempt and
/// can never sneak past the demote-only check by being unrecognised.
pub fn handler_rank(name: &str) -> u8 {
    if name == "textual" {
        return 0;
    }
    if matches!(
        name,
        "json" | "yaml" | "toml" | "xml" | "markdown" | "prose"
    ) {
        return 1;
    }
    if name.starts_with("tree-sitter:") && BUILTIN_HANDLERS.contains(&name) {
        return 2;
    }
    // Flow-control labels (ours-only / theirs-only / delete / no-auto /
    // none) never reach the cascade — they're synthesised by the merge
    // driver itself. Rank them at 0 so they're conservatively accepted
    // anywhere.
    if FLOW_HANDLERS.contains(&name) {
        return 0;
    }
    3
}

/// Layer a per-user override on top of a repository config (§6.6.3).
/// The override may add new rules and may *demote* a rule's handler
/// (replace it with a lower-rank one), but MUST NOT *promote* — the
/// motivating example is "I don't trust the Rust handler today, force
/// `*.rs` back to textual." Returns the merged config or, on
/// promotion attempt, the offending glob.
pub fn layer_local_over(
    repo: &MergeConfig,
    local: &MergeConfig,
) -> Result<MergeConfig, String> {
    let mut merged = repo.clone();
    for local_rule in &local.rules {
        let local_rank = handler_rank(&local_rule.handler);
        // For each matching glob in the repo config, the override
        // rank MUST be ≤ the existing rank. If the glob is new,
        // anything goes — there's no prior rank to compare against,
        // and the worst case is a path that previously fell to the
        // built-in default cascade.
        if let Some(existing) = repo.rules.iter().find(|r| r.glob == local_rule.glob) {
            let existing_rank = handler_rank(&existing.handler);
            if local_rank > existing_rank {
                return Err(format!(
                    "merge.local.toml may not promote handler aggressiveness: \
                     glob {:?} would go from rank {existing_rank} ({}) to \
                     rank {local_rank} ({})",
                    local_rule.glob, existing.handler, local_rule.handler
                ));
            }
        }
        // Replace the matching rule, or append.
        if let Some(slot) = merged.rules.iter_mut().find(|r| r.glob == local_rule.glob) {
            slot.handler = local_rule.handler.clone();
        } else {
            merged.rules.push(local_rule.clone());
        }
    }
    // Per-user config does NOT touch policy.allowed_handlers or
    // [[plugin]] entries — those live in repo config exclusively.
    // Local plugin sources would be a separate trust escalation.
    Ok(merged)
}

pub struct CascadeEngine {
    /// Handlers indexed by name.
    handlers: Vec<Arc<dyn MergeHandler>>,
    /// User-supplied rules; checked first in order.
    rules: Vec<MergeRule>,
    /// Always-applicable last-resort handler (textual).
    fallback: Arc<dyn MergeHandler>,
}

impl Default for CascadeEngine {
    fn default() -> Self {
        let textual: Arc<dyn MergeHandler> = Arc::new(TextualHandler);
        let mut handlers: Vec<Arc<dyn MergeHandler>> = vec![
            Arc::new(JsonHandler),
            Arc::new(TomlHandler),
            Arc::new(YamlHandler),
            Arc::new(MarkdownHandler),
            Arc::new(ProseHandler),
            Arc::new(XmlHandler),
        ];
        for lang in Lang::all() {
            handlers.push(Arc::new(TreeSitterHandler::new(*lang)));
        }
        handlers.push(textual.clone());
        Self {
            handlers,
            rules: Vec::new(),
            fallback: textual,
        }
    }
}

impl CascadeEngine {
    pub fn new() -> Self { Self::default() }

    pub fn with_config(mut self, cfg: MergeConfig) -> Self {
        self.rules = cfg.rules;
        self
    }

    /// Configure rules and load any `[[plugin]]` entries from disk. The
    /// callback `fetch` is invoked with `(name, source)` and must return the
    /// raw WASM bytes; this lets callers control where plugin modules come
    /// from (local cache, registered instance, etc.) without tying the merge
    /// engine to a fetch transport.
    pub fn with_config_and_plugins<F>(
        mut self,
        cfg: MergeConfig,
        mut fetch: F,
    ) -> Result<Self, String>
    where
        F: FnMut(&MergePluginEntry) -> Result<Vec<u8>, String>,
    {
        self.rules = cfg.rules;
        for entry in &cfg.plugins {
            let bytes = fetch(entry)?;
            let hash = parse_hash(&entry.hash)?;
            let plugin = PluginHandler::new(
                PluginConfig { name: entry.name.clone(), hash },
                &bytes,
            )
            .map_err(|e| format!("plugin {}: {e}", entry.name))?;
            self.handlers.push(Arc::new(plugin));
        }
        Ok(self)
    }

    pub fn register(&mut self, h: Arc<dyn MergeHandler>) {
        self.handlers.push(h);
    }

    /// Locate the handler that should run for `path`, considering rules then
    /// extension defaults.
    fn pick(&self, path: &Path) -> Option<Arc<dyn MergeHandler>> {
        let path_str = path.to_string_lossy();
        for rule in &self.rules {
            if let Ok(pat) = Pattern::new(&rule.glob) {
                if pat.matches(&path_str) {
                    if let Some(h) = self.handlers.iter().find(|h| h.name() == rule.handler) {
                        return Some(h.clone());
                    }
                }
            }
        }
        // Default cascade by extension.
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let pref: String = match ext {
            "json" => "json".into(),
            "toml" => "toml".into(),
            "yaml" | "yml" => "yaml".into(),
            "xml" | "svg" | "html" => "xml".into(),
            "md" | "markdown" => "markdown".into(),
            "txt" => "prose".into(),
            other => match Lang::from_extension(other) {
                Some(lang) => lang.handler_name().to_string(),
                None => "textual".into(),
            },
        };
        self.handlers.iter().find(|h| h.name() == pref).cloned()
    }

    pub fn merge_file(
        &self,
        path: &Path,
        base: &[u8],
        ours: &[u8],
        theirs: &[u8],
    ) -> MergeResult {
        if let Some(h) = self.pick(path) {
            if h.applicable(path, base, ours, theirs) {
                let result = h.merge(path, base, ours, theirs);
                if !matches!(result.status, MergeStatus::NotApplicable) {
                    return result;
                }
            }
        }
        // Fall through to textual.
        if self.fallback.applicable(path, base, ours, theirs) {
            return self.fallback.merge(path, base, ours, theirs);
        }
        MergeResult {
            handler: "none".into(),
            status: MergeStatus::Conflict {
                regions: vec![],
                partial: ours.to_vec(),
            },
        }
    }
}

/// Names of every handler that ships with the engine. Used by instance and
/// repository policy checks (§6.6.4) to expand the "builtin" alias and to
/// reject merge-record entries that reference unknown handlers.
pub const BUILTIN_HANDLERS: &[&str] = &[
    "json", "yaml", "toml", "xml", "markdown", "prose", "textual",
    "tree-sitter:rust", "tree-sitter:python", "tree-sitter:javascript",
    "tree-sitter:typescript", "tree-sitter:go", "tree-sitter:c",
    "tree-sitter:cpp", "tree-sitter:java", "tree-sitter:ruby",
    "tree-sitter:shell",
];

/// Names emitted by the merge driver itself for trivial flow-control
/// outcomes (kept only on one side, deletion honoured, etc.). They label
/// merge-record entries that did not actually invoke a handler, so they
/// always pass policy regardless of the allow list.
pub const FLOW_HANDLERS: &[&str] = &["ours-only", "theirs-only", "delete", "no-auto", "none"];

pub fn is_builtin_handler(name: &str) -> bool {
    BUILTIN_HANDLERS.iter().any(|b| *b == name)
        || FLOW_HANDLERS.iter().any(|b| *b == name)
}

/// Decide whether a `(handler, handler_hash)` tuple is permitted by the
/// supplied allow list. Semantics:
///
/// - Empty list → permissive (no enforcement).
/// - List containing `"builtin"` → all built-in handlers pass; explicit
///   `"name:blake3:<hex>"` entries also pass for plugins that pin to that
///   exact hash.
/// - List without `"builtin"` → only entries that match the explicit form
///   pass; built-ins are blocked (useful for an instance that wants to
///   forbid anything other than a vetted plugin set).
/// Validate every file entry of a merge-record against an allow list. Returns
/// the names of any handlers that violate the policy, in original order.
pub fn validate_record_against_policy(
    record: &crate::record::MergeRecord,
    allowed: &[String],
) -> Vec<String> {
    let mut bad = Vec::new();
    for fr in &record.files {
        if !check_handler_allowed(&fr.handler, &fr.handler_hash, allowed) {
            bad.push(fr.handler.clone());
        }
    }
    bad
}

pub fn check_handler_allowed(handler: &str, handler_hash: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let allows_builtin = allowed.iter().any(|s| s == "builtin");
    if allows_builtin && is_builtin_handler(handler) {
        return true;
    }
    let needle_with_hash = if handler_hash.is_empty() {
        None
    } else {
        let hash = handler_hash.strip_prefix("blake3:").unwrap_or(handler_hash);
        Some(format!("{handler}:blake3:{hash}"))
    };
    allowed.iter().any(|s| {
        s == handler
            || needle_with_hash.as_deref().map(|n| s == n).unwrap_or(false)
    })
}

fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.strip_prefix("blake3:").unwrap_or(s);
    if trimmed.len() != 64 {
        return Err(format!("expected 64-char blake3 hash, got {} chars", trimmed.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (trimmed.as_bytes()[i * 2] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex at byte {i}"))?;
        let lo = (trimmed.as_bytes()[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex at byte {i}"))?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

#[allow(dead_code)]
fn _path_unused(_: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hash_accepts_both_forms() {
        let h = "0".repeat(64);
        assert!(parse_hash(&h).is_ok());
        let prefixed = format!("blake3:{h}");
        assert_eq!(parse_hash(&h).unwrap(), parse_hash(&prefixed).unwrap());
    }

    #[test]
    fn parse_hash_rejects_short_input() {
        assert!(parse_hash("abc").is_err());
    }

    #[test]
    fn builtin_alias_admits_spec_handlers() {
        let allow = vec!["builtin".to_string()];
        assert!(check_handler_allowed("json", "", &allow));
        assert!(check_handler_allowed("tree-sitter:rust", "", &allow));
        assert!(!check_handler_allowed("tree-sitter:protobuf", "", &allow));
    }

    #[test]
    fn explicit_plugin_pin_admits_only_matching_hash() {
        let allow = vec![
            "builtin".into(),
            "tree-sitter:protobuf:blake3:abcd0000abcd0000abcd0000abcd0000abcd0000abcd0000abcd0000abcd0000".into(),
        ];
        let good = "abcd0000abcd0000abcd0000abcd0000abcd0000abcd0000abcd0000abcd0000";
        let bad = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        assert!(check_handler_allowed("tree-sitter:protobuf", good, &allow));
        assert!(!check_handler_allowed("tree-sitter:protobuf", bad, &allow));
    }

    #[test]
    fn empty_allow_list_is_permissive() {
        assert!(check_handler_allowed("anything", "", &[]));
    }

    #[test]
    fn flow_control_handler_names_always_pass() {
        let allow = vec!["builtin".into()];
        assert!(check_handler_allowed("ours-only", "", &allow));
        assert!(check_handler_allowed("delete", "", &allow));
    }

    #[test]
    fn handler_rank_matches_spec_tiers() {
        assert_eq!(handler_rank("textual"), 0);
        assert_eq!(handler_rank("json"), 1);
        assert_eq!(handler_rank("toml"), 1);
        assert_eq!(handler_rank("yaml"), 1);
        assert_eq!(handler_rank("xml"), 1);
        assert_eq!(handler_rank("markdown"), 1);
        assert_eq!(handler_rank("prose"), 1);
        assert_eq!(handler_rank("tree-sitter:rust"), 2);
        assert_eq!(handler_rank("tree-sitter:python"), 2);
        // Unknown / plugin-shaped names always rank as plugins so an
        // attacker can't sneak a promotion past the check by typoing.
        assert_eq!(handler_rank("tree-sitter:protobuf"), 3);
        assert_eq!(handler_rank("custom-plugin"), 3);
    }

    #[test]
    fn layer_local_demotes_rs_to_textual() {
        // Spec example verbatim: user pins `*.rs` back to textual when
        // they don't trust the Rust handler today.
        let repo = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "*.rs".into(),
                handler: "tree-sitter:rust".into(),
            }],
            plugins: vec![],
            policy: None,
        };
        let local = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "*.rs".into(),
                handler: "textual".into(),
            }],
            plugins: vec![],
            policy: None,
        };
        let merged = layer_local_over(&repo, &local).expect("demote allowed");
        assert_eq!(merged.rules.len(), 1);
        assert_eq!(merged.rules[0].handler, "textual");
    }

    #[test]
    fn layer_local_rejects_promotion() {
        // Repo config pins `*.rs` to textual; user tries to promote
        // it to tree-sitter. Spec says this MUST be rejected.
        let repo = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "*.rs".into(),
                handler: "textual".into(),
            }],
            plugins: vec![],
            policy: None,
        };
        let local = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "*.rs".into(),
                handler: "tree-sitter:rust".into(),
            }],
            plugins: vec![],
            policy: None,
        };
        let err = layer_local_over(&repo, &local).expect_err("must reject");
        assert!(err.contains("promote"), "error must mention promotion: {err}");
    }

    #[test]
    fn layer_local_appends_new_glob() {
        // No matching repo rule means the user's override establishes
        // a new policy. Anything goes — we accept it because there's
        // nothing to compare against.
        let repo = MergeConfig::default();
        let local = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "vendored/**".into(),
                handler: "textual".into(),
            }],
            plugins: vec![],
            policy: None,
        };
        let merged = layer_local_over(&repo, &local).unwrap();
        assert_eq!(merged.rules.len(), 1);
        assert_eq!(merged.rules[0].glob, "vendored/**");
    }

    #[test]
    fn layer_local_rejects_promotion_to_plugin() {
        let repo = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "*.proto".into(),
                handler: "textual".into(),
            }],
            plugins: vec![],
            policy: None,
        };
        let local = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "*.proto".into(),
                handler: "tree-sitter:protobuf".into(),
            }],
            plugins: vec![],
            policy: None,
        };
        assert!(layer_local_over(&repo, &local).is_err());
    }

    #[test]
    fn merge_config_parses_plugin_block() {
        let toml_src = r#"
            schema_version = 1
            [[rule]]
            glob = "*.proto"
            handler = "tree-sitter:protobuf"
            [[plugin]]
            name = "tree-sitter:protobuf"
            source = "https://example.com/p.wasm"
            hash = "blake3:0000000000000000000000000000000000000000000000000000000000000000"
        "#;
        let cfg: MergeConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.plugins.len(), 1);
        assert_eq!(cfg.plugins[0].name, "tree-sitter:protobuf");
    }
}

#[cfg(test)]
mod plugin_routing_tests {
    use super::*;

    const RETURN_OURS_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $top (mut i32) (i32.const 1024))
        (func (export "alloc") (param i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $top))
            (global.set $top (i32.add (global.get $top) (local.get 0)))
            (local.get $p))
        (func (export "merge")
            (param $bp i32) (param $bl i32)
            (param $op i32) (param $ol i32)
            (param $tp i32) (param $tl i32)
            (param $pp i32) (param $pl i32)
            (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ol)) (i64.const 32))
              (i64.extend_i32_u (local.get $op)))))
    "#;

    #[test]
    fn rule_routes_path_to_registered_plugin() {
        let bytes = wat::parse_str(RETURN_OURS_WAT).unwrap();
        let hash = blake3::hash(&bytes);
        let cfg = MergeConfig {
            schema_version: 1,
            rules: vec![MergeRule {
                glob: "*.proto".into(),
                handler: "test:plugin".into(),
            }],
            plugins: vec![MergePluginEntry {
                name: "test:plugin".into(),
                source: String::new(),
                hash: format!("blake3:{}", hash.to_hex()),
            }],
            policy: None,
        };
        let bytes_clone = bytes.clone();
        let engine = CascadeEngine::default()
            .with_config_and_plugins(cfg, move |_| Ok(bytes_clone.clone()))
            .expect("plugin loads with valid hash");
        let res = engine.merge_file(Path::new("schema.proto"), b"b", b"o", b"t");
        assert_eq!(res.handler, "test:plugin");
        match res.status {
            MergeStatus::Merged { content, .. } => assert_eq!(content, b"o"),
            other => panic!("expected Merged, got {other:?}"),
        }
    }
}
