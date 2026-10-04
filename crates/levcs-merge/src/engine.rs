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

/// Check `merge.local.toml` rules against the repository's (§6.6.3).
///
/// A local rule may keep the repository's handler for its pattern or choose
/// `textual`, and nothing else. The old rule ranked handlers and refused
/// only a step up in rank, which still let a local rule switch between
/// unrelated structural handlers, or name any handler at all under a new
/// pattern. This check is per pattern. `CascadeEngine::select` repeats it
/// per path, which also catches local patterns that overlap the
/// repository's differently.
pub fn check_local_rules(repo: &MergeConfig, local: &MergeConfig) -> Result<(), String> {
    for rule in &local.rules {
        if rule.handler == "textual" {
            continue;
        }
        match repo.rules.iter().find(|r| r.glob == rule.glob) {
            Some(r) if r.handler == rule.handler => {}
            Some(r) => {
                return Err(format!(
                    "merge.local.toml may only keep the repository's handler or choose \
                     textual: glob {:?} is {} in the repository, not {}",
                    rule.glob, r.handler, rule.handler
                ))
            }
            None => {
                return Err(format!(
                    "merge.local.toml may only keep the repository's handler or choose \
                     textual: glob {:?} is not in the repository's merge.toml, so it can \
                     only be textual, not {}",
                    rule.glob, rule.handler
                ))
            }
        }
    }
    if !local.plugins.is_empty() {
        return Err("merge.local.toml may not declare plugins".into());
    }
    Ok(())
}

pub struct CascadeEngine {
    /// Handlers indexed by name.
    handlers: Vec<Arc<dyn MergeHandler>>,
    /// The repository's rules, in order; the first match selects.
    rules: Vec<MergeRule>,
    /// Per-user rules from `merge.local.toml`, in order. A matching one may
    /// only keep the repository's choice for the path or choose `textual`.
    local_rules: Vec<MergeRule>,
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
            local_rules: Vec::new(),
            fallback: textual,
        }
    }
}

impl CascadeEngine {
    pub fn new() -> Self {
        Self::default()
    }

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
                PluginConfig {
                    name: entry.name.clone(),
                    hash,
                },
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

    /// Add `merge.local.toml` rules over the repository's, after checking
    /// them with [`check_local_rules`].
    pub fn with_local_overrides(
        mut self,
        repo: &MergeConfig,
        local: &MergeConfig,
    ) -> Result<Self, String> {
        check_local_rules(repo, local)?;
        self.local_rules = local.rules.clone();
        Ok(self)
    }

    /// Every rule must name a registered handler. A rule naming an unknown
    /// handler used to fall through silently to the extension default, so
    /// a typo changed how files merged without saying so.
    pub fn validate(&self) -> Result<(), String> {
        for rule in self.rules.iter().chain(&self.local_rules) {
            Pattern::new(&rule.glob)
                .map_err(|e| format!("merge rule glob {:?} is invalid: {e}", rule.glob))?;
            if !self.handlers.iter().any(|h| h.name() == rule.handler) {
                return Err(format!(
                    "merge rule for {:?} names handler {:?}, which is not available",
                    rule.glob, rule.handler
                ));
            }
        }
        Ok(())
    }

    fn first_match<'r>(rules: &'r [MergeRule], path: &str) -> Option<&'r MergeRule> {
        rules.iter().find(|r| {
            Pattern::new(&r.glob)
                .map(|p| p.matches(path))
                .unwrap_or(false)
        })
    }

    /// The handler that merges `path`. Without a matching rule, `textual`.
    ///
    /// The structural handlers used to be the default by file extension,
    /// and they lose, invent and reorder content under disjoint edits while
    /// reporting a clean merge (audit 2026-10-03, finding C5). They now run
    /// only where the repository's `merge.toml` selects them. A matching
    /// local rule may keep that choice or choose `textual`; any other choice
    /// is an error naming the rule.
    pub fn select(&self, path: &Path) -> Result<String, String> {
        let p = path.to_string_lossy();
        let repo_choice = Self::first_match(&self.rules, &p)
            .map(|r| r.handler.clone())
            .unwrap_or_else(|| "textual".to_string());
        match Self::first_match(&self.local_rules, &p) {
            None => Ok(repo_choice),
            Some(l) if l.handler == "textual" => Ok("textual".into()),
            Some(l) if l.handler == repo_choice => Ok(repo_choice),
            Some(l) => Err(format!(
                "merge.local.toml rule {:?} selects {} for {p}, where the repository \
                 selects {repo_choice}; a local rule may only keep that or choose textual",
                l.glob, l.handler
            )),
        }
    }

    /// The handler for `path`. Callers check [`Self::select`] first; if a
    /// local rule is invalid for this path, merge with `textual`.
    fn pick(&self, path: &Path) -> Option<Arc<dyn MergeHandler>> {
        let name = self.select(path).unwrap_or_else(|_| "textual".into());
        self.handlers.iter().find(|h| h.name() == name).cloned()
    }

    pub fn merge_file(&self, path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        // Binary content is never merged by a built-in handler, whichever
        // one the configuration selects: divergent edits stay a conflict,
        // and the working file keeps ours, byte for byte. A plugin selected
        // by rule decides for itself.
        let binary = crate::textual::looks_binary(base)
            || crate::textual::looks_binary(ours)
            || crate::textual::looks_binary(theirs);
        let selected = self.pick(path);
        if binary
            && selected
                .as_ref()
                .is_none_or(|h| is_builtin_handler(h.name()))
        {
            return MergeResult {
                handler: "none".into(),
                status: MergeStatus::Conflict {
                    regions: vec![],
                    partial: ours.to_vec(),
                },
            };
        }
        if let Some(h) = selected {
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
    "json",
    "yaml",
    "toml",
    "xml",
    "markdown",
    "prose",
    "textual",
    "tree-sitter:rust",
    "tree-sitter:python",
    "tree-sitter:javascript",
    "tree-sitter:typescript",
    "tree-sitter:go",
    "tree-sitter:c",
    "tree-sitter:cpp",
    "tree-sitter:java",
    "tree-sitter:ruby",
    "tree-sitter:shell",
];

/// Names emitted by the merge driver itself for trivial flow-control
/// outcomes (kept only on one side, deletion honoured, etc.). They label
/// merge-record entries that did not actually invoke a handler, so they
/// always pass policy regardless of the allow list.
pub const FLOW_HANDLERS: &[&str] = &["ours-only", "theirs-only", "delete", "no-auto", "none"];

pub fn is_builtin_handler(name: &str) -> bool {
    BUILTIN_HANDLERS.iter().any(|b| *b == name) || FLOW_HANDLERS.iter().any(|b| *b == name)
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
    allowed
        .iter()
        .any(|s| s == handler || needle_with_hash.as_deref().map(|n| s == n).unwrap_or(false))
}

fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.strip_prefix("blake3:").unwrap_or(s);
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64-char blake3 hash, got {} chars",
            trimmed.len()
        ));
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

    fn rules(pairs: &[(&str, &str)]) -> MergeConfig {
        MergeConfig {
            schema_version: 1,
            rules: pairs
                .iter()
                .map(|(g, h)| MergeRule {
                    glob: g.to_string(),
                    handler: h.to_string(),
                })
                .collect(),
            plugins: vec![],
            policy: None,
        }
    }

    #[test]
    fn without_a_rule_every_file_merges_textually() {
        let e = CascadeEngine::default();
        for p in [
            "a.json", "b.md", "c.rs", "d.toml", "e.yaml", "f.py", "g.txt", "h",
        ] {
            assert_eq!(e.select(Path::new(p)).unwrap(), "textual", "{p}");
        }
        let r = e.merge_file(Path::new("x.json"), b"{}\n", b"{\"a\":1}\n", b"{}\n");
        assert_eq!(r.handler, "textual");
    }

    #[test]
    fn a_repository_rule_opts_a_path_into_a_structural_handler() {
        let e = CascadeEngine::default().with_config(rules(&[("*.json", "json")]));
        assert_eq!(e.select(Path::new("a.json")).unwrap(), "json");
        assert_eq!(e.select(Path::new("a.md")).unwrap(), "textual");
    }

    #[test]
    fn a_local_rule_may_keep_the_repository_handler_or_choose_textual() {
        let repo = rules(&[("*.rs", "tree-sitter:rust")]);
        let keep = rules(&[("*.rs", "tree-sitter:rust")]);
        let demote = rules(&[("*.rs", "textual"), ("vendored/**", "textual")]);
        let e = CascadeEngine::default()
            .with_config(repo.clone())
            .with_local_overrides(&repo, &keep)
            .unwrap();
        assert_eq!(e.select(Path::new("a.rs")).unwrap(), "tree-sitter:rust");
        let e = CascadeEngine::default()
            .with_config(repo.clone())
            .with_local_overrides(&repo, &demote)
            .unwrap();
        assert_eq!(e.select(Path::new("a.rs")).unwrap(), "textual");
        assert_eq!(e.select(Path::new("vendored/x.c")).unwrap(), "textual");
    }

    #[test]
    fn a_local_rule_cannot_switch_structural_handlers_or_add_one() {
        let repo = rules(&[("*.rs", "tree-sitter:rust"), ("*.md", "textual")]);
        // Same rank as the repository's handler, but a different handler.
        let switch = rules(&[("*.rs", "tree-sitter:python")]);
        assert!(check_local_rules(&repo, &switch).is_err());
        // A new pattern can only be textual.
        let new_pattern = rules(&[("*.json", "json")]);
        assert!(check_local_rules(&repo, &new_pattern).is_err());
        // A repository textual rule cannot be raised.
        let raise = rules(&[("*.md", "markdown")]);
        assert!(check_local_rules(&repo, &raise).is_err());
    }

    #[test]
    fn overlapping_local_patterns_are_checked_per_path() {
        // The repository selects textual for special/*.json and json
        // elsewhere. A local *.json -> json passes the per-pattern check
        // (it keeps the repository's *.json choice) but would promote
        // special/a.json, so selecting that path is an error.
        let repo = rules(&[("special/*.json", "textual"), ("*.json", "json")]);
        let local = rules(&[("*.json", "json")]);
        let e = CascadeEngine::default()
            .with_config(repo.clone())
            .with_local_overrides(&repo, &local)
            .unwrap();
        assert_eq!(e.select(Path::new("a.json")).unwrap(), "json");
        let err = e.select(Path::new("special/a.json")).unwrap_err();
        assert!(err.contains("special/a.json"), "{err}");
        // pick never promotes, even if a caller skips select.
        let r = e.merge_file(
            Path::new("special/a.json"),
            b"{}\n",
            b"{}\n",
            b"{\"x\":1}\n",
        );
        assert_eq!(r.handler, "textual");
    }

    #[test]
    fn duplicate_rules_resolve_to_the_first_match() {
        // Duplicate repository globs: the first one is the repository's
        // choice, and a local rule keeping a later duplicate's handler is
        // not keeping the repository's choice.
        let repo = rules(&[("*.json", "textual"), ("*.json", "json")]);
        let e = CascadeEngine::default().with_config(repo.clone());
        assert_eq!(e.select(Path::new("a.json")).unwrap(), "textual");
        assert!(check_local_rules(&repo, &rules(&[("*.json", "json")])).is_err());
        // Duplicate local globs: the first matching local rule applies.
        let repo = rules(&[("*.json", "json")]);
        let local = rules(&[("*.json", "textual"), ("*.json", "json")]);
        let e = CascadeEngine::default()
            .with_config(repo.clone())
            .with_local_overrides(&repo, &local)
            .unwrap();
        assert_eq!(e.select(Path::new("a.json")).unwrap(), "textual");
    }

    #[test]
    fn a_rule_naming_an_unavailable_handler_is_an_error() {
        let e = CascadeEngine::default().with_config(rules(&[("*.proto", "protobuf")]));
        assert!(e.validate().is_err());
        let e = CascadeEngine::default().with_config(rules(&[("*.json", "json")]));
        assert!(e.validate().is_ok());
    }

    #[test]
    fn binary_input_reaches_no_builtin_handler_even_by_rule() {
        // A Markdown handler accepts NUL-containing UTF-8, so the guard is in
        // the engine, not only in the textual handler's applicability.
        let e = CascadeEngine::default().with_config(rules(&[("*.md", "markdown")]));
        for (base, ours, theirs) in [
            (&b"\0a\n"[..], &b"\0b\n"[..], &b"\0a\n\0c\n"[..]),
            (&b"a\n"[..], &b"\xffb\n"[..], &b"a\nc\n"[..]),
        ] {
            let r = e.merge_file(Path::new("x.md"), base, ours, theirs);
            assert_eq!(r.handler, "none");
            match r.status {
                MergeStatus::Conflict { partial, .. } => assert_eq!(partial, ours),
                other => panic!("binary input merged: {other:?}"),
            }
        }
        assert!(crate::textual::looks_binary(b"text\0"));
        assert!(!crate::textual::looks_binary(
            "plain text, ünïcode".as_bytes()
        ));
    }

    #[test]
    fn the_textual_handler_itself_refuses_binary_input() {
        // The engine guard covers built-in selections; this covers the
        // fall-through to textual after a selected plugin declines a file.
        let t = crate::textual::TextualHandler;
        assert!(!t.applicable(Path::new("x"), b"\0a\n", b"\0b\n", b"\0c\n"));
        assert!(!t.applicable(Path::new("x"), b"a\n", b"\xff\n", b"c\n"));
        assert!(t.applicable(Path::new("x"), b"a\n", b"b\n", b"c\n"));
    }

    #[test]
    fn local_config_cannot_declare_plugins() {
        let mut local = rules(&[]);
        local.plugins.push(MergePluginEntry {
            name: "p".into(),
            source: String::new(),
            hash: "0".repeat(64),
        });
        assert!(check_local_rules(&MergeConfig::default(), &local).is_err());
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
