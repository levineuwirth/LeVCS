//! Tree-sitter handler (§6.3.2).
//!
//! Parses base, ours, and theirs with a tree-sitter grammar and performs a
//! structural three-way merge over the named children of the source root,
//! recursing into nested blocks when both sides modify the same outer
//! block (e.g., two engineers each adding a different method to the same
//! `impl` / `class`).
//!
//! Algorithm:
//!   1. Parse all three. If any parse produces a tree with errors, return
//!      `NotApplicable`; the cascade then falls through to the textual
//!      handler (§6.3.3).
//!   2. Extract top-level named children. Each child is identified by
//!      `(kind, name)` where `name` comes from the grammar's `name` /
//!      `declarator` field; or, for nodes without a recoverable name, by
//!      `(kind, blake3(text))` so that identical anonymous items collapse.
//!   3. Three-way merge over the union of identities: independent
//!      additions/deletions/modifications are auto-resolved.
//!   4. When both sides modify the same identity AND the language is one
//!      whose containers don't depend on indentation, attempt **recursive
//!      merge**: descend into that block's body, treat its named children
//!      as the new identity space, run the same algorithm. Only commit
//!      the recursive result when the outer "frame" (everything in the
//!      block that isn't the body) is identical between ours and theirs
//!      *and* the inner merge is conflict-free. Anything else falls back
//!      to a block-level conflict.
//!   5. Reconstruct the file by emitting kept blocks in ours's source
//!      order, then appending blocks added only by theirs. Top-level
//!      blocks are joined with a blank line; recursive splices preserve
//!      the inter-child glue (whitespace, indentation) of ours's body.
//!
//! Conflict granularity is the smallest named container in which the
//! conflict is genuinely unresolvable. Concurrent edits inside the same
//! method body still produce a single block-level conflict at that
//! method, since method bodies generally lack the structural identity
//! recursion needs.

use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;

use tree_sitter::{Language, Node, Parser, Tree};

use crate::handler::{ConflictRegion, MergeHandler, MergeNote, MergeResult, MergeStatus};

/// One of the languages shipped with the built-in handler set (§6.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    C,
    Cpp,
    Java,
    Ruby,
    Shell,
}

impl Lang {
    pub fn handler_name(self) -> &'static str {
        match self {
            Lang::Rust => "tree-sitter:rust",
            Lang::Python => "tree-sitter:python",
            Lang::JavaScript => "tree-sitter:javascript",
            Lang::TypeScript => "tree-sitter:typescript",
            Lang::Go => "tree-sitter:go",
            Lang::C => "tree-sitter:c",
            Lang::Cpp => "tree-sitter:cpp",
            Lang::Java => "tree-sitter:java",
            Lang::Ruby => "tree-sitter:ruby",
            Lang::Shell => "tree-sitter:shell",
        }
    }

    pub fn from_extension(ext: &str) -> Option<Lang> {
        match ext {
            "rs" => Some(Lang::Rust),
            "py" => Some(Lang::Python),
            "js" | "mjs" => Some(Lang::JavaScript),
            "ts" => Some(Lang::TypeScript),
            "go" => Some(Lang::Go),
            "c" | "h" => Some(Lang::C),
            "cpp" | "cc" | "hpp" => Some(Lang::Cpp),
            "java" => Some(Lang::Java),
            "rb" => Some(Lang::Ruby),
            "sh" | "bash" => Some(Lang::Shell),
            _ => None,
        }
    }

    fn language(self) -> Language {
        match self {
            Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
            Lang::Python => tree_sitter_python::LANGUAGE.into(),
            Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Lang::Go => tree_sitter_go::LANGUAGE.into(),
            Lang::C => tree_sitter_c::LANGUAGE.into(),
            Lang::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Lang::Java => tree_sitter_java::LANGUAGE.into(),
            Lang::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Lang::Shell => tree_sitter_bash::LANGUAGE.into(),
        }
    }

    pub fn all() -> &'static [Lang] {
        &[
            Lang::Rust,
            Lang::Python,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Go,
            Lang::C,
            Lang::Cpp,
            Lang::Java,
            Lang::Ruby,
            Lang::Shell,
        ]
    }

    /// Brace-delimited languages can be safely re-emitted block-by-block
    /// without breaking the parse, so recursion is sound. Indentation-
    /// sensitive grammars (Python, Ruby) and the shell can't tolerate the
    /// child-list reformatting recursion does, so we keep them at
    /// top-level granularity. The on-wire/test behaviour for these is
    /// unchanged from the previous flat implementation.
    fn supports_recursion(self) -> bool {
        matches!(
            self,
            Lang::Rust
                | Lang::JavaScript
                | Lang::TypeScript
                | Lang::Go
                | Lang::C
                | Lang::Cpp
                | Lang::Java
        )
    }
}

pub struct TreeSitterHandler {
    lang: Lang,
}

impl TreeSitterHandler {
    pub fn new(lang: Lang) -> Self { Self { lang } }

    fn parse(&self, src: &[u8]) -> Option<Tree> {
        let mut p = Parser::new();
        p.set_language(&self.lang.language()).ok()?;
        let tree = p.parse(src, None)?;
        if tree.root_node().has_error() {
            return None;
        }
        Some(tree)
    }
}

#[derive(Clone, Debug)]
struct Block {
    kind: String,
    key: BlockKey,
    range: Range<usize>,
    text: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum BlockKey {
    Named(String, String),
    Anon(String, [u8; 32]),
}

/// State threaded through every level of recursion: the parsed trees and
/// raw source bytes for each side, plus the language. The recursive
/// helpers use it to find a Block's original Node (so they can read its
/// `body` field) without having to thread Node references — Node
/// lifetimes are tied to a specific Tree borrow and don't compose well
/// with the Block struct.
struct RecurseCtx<'a> {
    lang: Lang,
    base_tree: &'a Tree,
    ours_tree: &'a Tree,
    theirs_tree: &'a Tree,
    base_src: &'a [u8],
    ours_src: &'a [u8],
    theirs_src: &'a [u8],
}

fn extract_name(node: Node, src: &[u8]) -> Option<String> {
    if let Some(n) = node.child_by_field_name("name") {
        if let Ok(t) = n.utf8_text(src) {
            return Some(t.to_string());
        }
    }
    // Rust `impl_item` has no `name` field — its identity is determined
    // by the (optional) trait and the type being implemented. We
    // synthesise "Trait for Type" / "Type" as the identity so two
    // different sides editing the same impl block actually match up.
    // Without this they fall through to the anonymous-hash key and get
    // treated as unrelated additions.
    if node.kind() == "impl_item" {
        let trait_name = node
            .child_by_field_name("trait")
            .and_then(|n| n.utf8_text(src).ok());
        let type_name = node
            .child_by_field_name("type")
            .and_then(|n| n.utf8_text(src).ok());
        match (trait_name, type_name) {
            (Some(tr), Some(ty)) => return Some(format!("{tr} for {ty}")),
            (None, Some(ty)) => return Some(ty.to_string()),
            _ => {}
        }
    }
    if let Some(n) = node.child_by_field_name("declarator") {
        if let Some(name) = extract_name(n, src) {
            return Some(name);
        }
        let mut cur = n.walk();
        for child in n.named_children(&mut cur) {
            if matches!(
                child.kind(),
                "identifier" | "type_identifier" | "field_identifier"
            ) {
                if let Ok(t) = child.utf8_text(src) {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

fn block_from_node(node: Node, src: &[u8]) -> Block {
    let kind = node.kind().to_string();
    let range = node.byte_range();
    let text = src[range.clone()].to_vec();
    let key = match extract_name(node, src) {
        Some(n) => BlockKey::Named(kind.clone(), n),
        None => BlockKey::Anon(kind.clone(), *blake3::hash(&text).as_bytes()),
    };
    Block { kind, key, range, text }
}

fn top_level_blocks(tree: &Tree, src: &[u8]) -> Vec<Block> {
    let root = tree.root_node();
    let mut cur = root.walk();
    root.named_children(&mut cur)
        .map(|n| block_from_node(n, src))
        .collect()
}

/// Children of a body container (the named-block-bearing direct children).
/// Used during recursion to obtain the inner identity space of a
/// container node like `class_body`, `declaration_list`, `block`, etc.
fn body_children(body: Node, src: &[u8]) -> Vec<Block> {
    let mut cur = body.walk();
    body.named_children(&mut cur)
        .map(|n| block_from_node(n, src))
        .collect()
}

/// Locate the AST node within `tree` whose byte range matches `target`
/// exactly. Implemented as a guided descent that prunes any subtree whose
/// own byte range doesn't span the target — O(depth × siblings) in
/// practice, plenty fast since recursion is only attempted on conflict.
fn find_named_node<'a>(tree: &'a Tree, target: &Range<usize>) -> Option<Node<'a>> {
    fn search<'b>(n: Node<'b>, target: &Range<usize>) -> Option<Node<'b>> {
        if n.byte_range() == *target {
            return Some(n);
        }
        if n.start_byte() > target.start || n.end_byte() < target.end {
            return None;
        }
        let mut cur = n.walk();
        for c in n.named_children(&mut cur) {
            if let Some(found) = search(c, target) {
                return Some(found);
            }
        }
        None
    }
    search(tree.root_node(), target)
}

fn lookup<'a>(blocks: &'a [Block], key: &BlockKey) -> Option<&'a Block> {
    blocks.iter().find(|b| &b.key == key)
}

fn make_region(
    kind: &str,
    desc: &str,
    base: Option<&Block>,
    ours: Option<&Block>,
    theirs: Option<&Block>,
) -> ConflictRegion {
    fn r(b: Option<&Block>) -> Range<usize> {
        b.map(|b| b.range.clone()).unwrap_or(0..0)
    }
    ConflictRegion {
        description: format!("{desc} on {kind}"),
        base: r(base),
        ours: r(ours),
        theirs: r(theirs),
    }
}

fn conflict_marker_block(ours: &[u8], theirs: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"<<<<<<< ours\n");
    out.extend_from_slice(ours);
    if !ours.is_empty() && !ours.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(b"=======\n");
    out.extend_from_slice(theirs);
    if !theirs.is_empty() && !theirs.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(b">>>>>>> theirs");
    out
}

fn join_blocks_with(blocks: &[Vec<u8>], sep: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(b);
    }
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

fn join_top_level(blocks: &[Vec<u8>]) -> Vec<u8> {
    join_blocks_with(blocks, b"\n\n")
}

/// Result of a per-block merge operation: the bytes to emit (possibly
/// containing conflict markers) plus any conflict regions and notes the
/// caller should surface to the user. Splitting the (text, conflicts)
/// pair from the joining step lets recursive callers preserve ours's
/// inter-child glue when reconstructing a parent block's body.
struct InnerMerge {
    blocks: Vec<Vec<u8>>,
    conflicts: Vec<ConflictRegion>,
    notes: Vec<MergeNote>,
    had_conflict: bool,
}

fn merge_blocks_inner(
    base: &[Block],
    ours: &[Block],
    theirs: &[Block],
    ctx: Option<&RecurseCtx>,
) -> InnerMerge {
    let mut emitted: HashSet<BlockKey> = HashSet::new();
    let mut output: Vec<Vec<u8>> = Vec::new();
    let mut conflicts: Vec<ConflictRegion> = Vec::new();
    let mut notes: Vec<MergeNote> = Vec::new();
    let mut had_conflict = false;

    for o in ours {
        if !emitted.insert(o.key.clone()) {
            continue;
        }
        let b = lookup(base, &o.key);
        let t = lookup(theirs, &o.key);
        match (b, t) {
            (None, None) => {
                output.push(o.text.clone());
            }
            (None, Some(tb)) => {
                if o.text == tb.text {
                    output.push(o.text.clone());
                } else {
                    had_conflict = true;
                    conflicts.push(make_region(&o.kind, "concurrent additions diverge", None, Some(o), Some(tb)));
                    output.push(conflict_marker_block(&o.text, &tb.text));
                }
            }
            (Some(bb), None) => {
                if o.text == bb.text {
                    // ours unchanged, theirs deleted → honour deletion
                } else {
                    had_conflict = true;
                    conflicts.push(make_region(&o.kind, "modify-vs-delete", Some(bb), Some(o), None));
                    output.push(conflict_marker_block(&o.text, &[]));
                    notes.push(MergeNote {
                        message: format!("{}: modified by ours, deleted by theirs", o.kind),
                    });
                }
            }
            (Some(bb), Some(tb)) => {
                let ours_changed = o.text != bb.text;
                let theirs_changed = tb.text != bb.text;
                match (ours_changed, theirs_changed) {
                    (false, false) => output.push(o.text.clone()),
                    (true, false) => output.push(o.text.clone()),
                    (false, true) => output.push(tb.text.clone()),
                    (true, true) => {
                        if o.text == tb.text {
                            output.push(o.text.clone());
                            notes.push(MergeNote {
                                message: format!("{}: identical edits on both sides", o.kind),
                            });
                        } else if let Some(merged) =
                            ctx.and_then(|c| try_recursive_clean(c, bb, o, tb))
                        {
                            output.push(merged);
                            notes.push(MergeNote {
                                message: format!(
                                    "{}: merged disjoint edits via recursive descent",
                                    o.kind
                                ),
                            });
                        } else {
                            had_conflict = true;
                            conflicts.push(make_region(
                                &o.kind,
                                "concurrent edits",
                                Some(bb),
                                Some(o),
                                Some(tb),
                            ));
                            output.push(conflict_marker_block(&o.text, &tb.text));
                        }
                    }
                }
            }
        }
    }

    for t in theirs {
        if emitted.contains(&t.key) {
            continue;
        }
        emitted.insert(t.key.clone());
        let b = lookup(base, &t.key);
        match b {
            None => {
                output.push(t.text.clone());
            }
            Some(bb) => {
                if t.text == bb.text {
                    // theirs unchanged, ours deleted → honour deletion
                } else {
                    had_conflict = true;
                    conflicts.push(make_region(&t.kind, "delete-vs-modify", Some(bb), None, Some(t)));
                    output.push(conflict_marker_block(&[], &t.text));
                    notes.push(MergeNote {
                        message: format!("{}: deleted by ours, modified by theirs", t.kind),
                    });
                }
            }
        }
    }

    InnerMerge { blocks: output, conflicts, notes, had_conflict }
}

/// Try to merge a single conflicted block by descending into its body and
/// merging its inner named children. Returns `Some(text)` on success —
/// the bytes that should replace the would-have-been conflict marker —
/// and `None` on any of:
///   - language doesn't support recursion (indent-sensitive),
///   - no `body` field on either side's outer node,
///   - outer "frame" (text outside the body) differs between ours and
///     theirs, meaning the header/footer themselves conflict,
///   - the block has no identifiable inner structure (all anonymous),
///   - the recursive child merge produced any conflict.
///
/// On success, the splice preserves ours's body prefix (text before the
/// first inner child), suffix (text after the last inner child), and
/// inter-child separator (the glue used between ours's first two
/// children, defaulting to `\n\n`). This keeps indentation and bracing
/// style consistent with ours rather than emitting a stylistically dead
/// `\n\n`-joined list — important because recursive merges land in
/// downstream review tools and uglier output is harder to skim.
fn try_recursive_clean(
    ctx: &RecurseCtx,
    base: &Block,
    ours: &Block,
    theirs: &Block,
) -> Option<Vec<u8>> {
    if !ctx.lang.supports_recursion() {
        return None;
    }

    let base_node = find_named_node(ctx.base_tree, &base.range)?;
    let ours_node = find_named_node(ctx.ours_tree, &ours.range)?;
    let theirs_node = find_named_node(ctx.theirs_tree, &theirs.range)?;

    let base_body = base_node.child_by_field_name("body")?;
    let ours_body = ours_node.child_by_field_name("body")?;
    let theirs_body = theirs_node.child_by_field_name("body")?;

    let oo = ours_node.byte_range();
    let oob = ours_body.byte_range();
    let to = theirs_node.byte_range();
    let tob = theirs_body.byte_range();

    // Frame = the outer block bytes outside the body. If those differ
    // between ours and theirs, the *header* (or footer) itself is in
    // conflict — recursing would silently discard one side's edit.
    let ours_prefix = &ctx.ours_src[oo.start..oob.start];
    let ours_suffix = &ctx.ours_src[oob.end..oo.end];
    let theirs_prefix = &ctx.theirs_src[to.start..tob.start];
    let theirs_suffix = &ctx.theirs_src[tob.end..to.end];
    if ours_prefix != theirs_prefix || ours_suffix != theirs_suffix {
        return None;
    }

    let bc = body_children(base_body, ctx.base_src);
    let oc = body_children(ours_body, ctx.ours_src);
    let tc = body_children(theirs_body, ctx.theirs_src);

    if bc.is_empty() && oc.is_empty() && tc.is_empty() {
        return None;
    }
    // Recursion only buys something when at least one of the inner blocks
    // has a recoverable identity. If everything is anonymous, body diffs
    // collapse to text-level and we'd match arbitrary content together.
    if bc.iter().chain(&oc).chain(&tc).all(|b| matches!(b.key, BlockKey::Anon(..))) {
        return None;
    }

    let inner = merge_blocks_inner(&bc, &oc, &tc, Some(ctx));
    if inner.had_conflict {
        return None;
    }

    // Splice the merged inner blocks back into ours's outer text. We use
    // ours's body slot — its prefix, suffix, and inter-child separator —
    // so the spliced result matches ours's existing style.
    let body_rel_start = oob.start - oo.start;
    let body_rel_end = oob.end - oo.start;
    let body_text = &ours.text[body_rel_start..body_rel_end];
    let (prefix, suffix) = body_prefix_suffix(body_text, &oc, oob.start);
    let sep = inter_child_separator(body_text, &oc, oob.start);
    let merged_children = join_blocks_with(&inner.blocks, &sep);
    // join_blocks_with appends a trailing newline to keep top-level files
    // POSIX-compliant; that's the wrong choice when splicing into the
    // middle of an outer block — the suffix already carries whatever the
    // body ended with.
    let merged_children = strip_trailing_newline(&merged_children);

    let mut out = Vec::new();
    out.extend_from_slice(&ours.text[..body_rel_start]);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&merged_children);
    out.extend_from_slice(suffix);
    out.extend_from_slice(&ours.text[body_rel_end..]);
    Some(out)
}

fn body_prefix_suffix<'a>(
    body_text: &'a [u8],
    children: &[Block],
    body_start_abs: usize,
) -> (&'a [u8], &'a [u8]) {
    if children.is_empty() {
        return (body_text, &[]);
    }
    let first_rel = children[0].range.start - body_start_abs;
    let last_rel = children.last().unwrap().range.end - body_start_abs;
    (&body_text[..first_rel], &body_text[last_rel..])
}

fn inter_child_separator(
    body_text: &[u8],
    children: &[Block],
    body_start_abs: usize,
) -> Vec<u8> {
    if children.len() < 2 {
        return b"\n\n".to_vec();
    }
    let end_first = children[0].range.end - body_start_abs;
    let start_second = children[1].range.start - body_start_abs;
    body_text[end_first..start_second].to_vec()
}

fn strip_trailing_newline(b: &[u8]) -> Vec<u8> {
    if b.ends_with(b"\n") {
        b[..b.len() - 1].to_vec()
    } else {
        b.to_vec()
    }
}

impl MergeHandler for TreeSitterHandler {
    fn name(&self) -> &str { self.lang.handler_name() }

    fn applicable(&self, _path: &Path, _base: &[u8], _ours: &[u8], _theirs: &[u8]) -> bool {
        // Applicability is decided in `merge`; if any input fails to parse
        // we return NotApplicable and the cascade advances to textual.
        true
    }

    fn merge(&self, _path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let (b_tree, o_tree, t_tree) =
            match (self.parse(base), self.parse(ours), self.parse(theirs)) {
                (Some(b), Some(o), Some(t)) => (b, o, t),
                _ => {
                    return MergeResult {
                        handler: self.name().to_string(),
                        status: MergeStatus::NotApplicable,
                    };
                }
            };
        let bb = top_level_blocks(&b_tree, base);
        let ob = top_level_blocks(&o_tree, ours);
        let tb = top_level_blocks(&t_tree, theirs);
        if bb.is_empty() && ob.is_empty() && tb.is_empty() {
            return MergeResult {
                handler: self.name().to_string(),
                status: MergeStatus::NotApplicable,
            };
        }
        let ctx = RecurseCtx {
            lang: self.lang,
            base_tree: &b_tree,
            ours_tree: &o_tree,
            theirs_tree: &t_tree,
            base_src: base,
            ours_src: ours,
            theirs_src: theirs,
        };
        let inner = merge_blocks_inner(&bb, &ob, &tb, Some(&ctx));
        let merged = join_top_level(&inner.blocks);
        if inner.had_conflict {
            MergeResult {
                handler: self.name().to_string(),
                status: MergeStatus::Conflict {
                    regions: inner.conflicts,
                    partial: merged,
                },
            }
        } else {
            MergeResult {
                handler: self.name().to_string(),
                status: MergeStatus::Merged {
                    content: merged,
                    notes: inner.notes,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::CascadeEngine;
    use std::path::Path;

    fn run(lang: Lang, base: &str, ours: &str, theirs: &str) -> MergeResult {
        let h = TreeSitterHandler::new(lang);
        h.merge(Path::new("file"), base.as_bytes(), ours.as_bytes(), theirs.as_bytes())
    }

    #[test]
    fn rust_disjoint_function_additions_merge() {
        let base = "fn a() {}\n";
        let ours = "fn a() {}\n\nfn b() {}\n";
        let theirs = "fn a() {}\n\nfn c() {}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        assert_eq!(result.handler, "tree-sitter:rust");
        match result.status {
            MergeStatus::Merged { content, .. } => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains("fn a()"));
                assert!(s.contains("fn b()"));
                assert!(s.contains("fn c()"));
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn rust_concurrent_edits_to_same_function_conflict() {
        let base = "fn greet() {\n    println!(\"hi\");\n}\n";
        let ours = "fn greet() {\n    println!(\"hello\");\n}\n";
        let theirs = "fn greet() {\n    println!(\"hey\");\n}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        match result.status {
            MergeStatus::Conflict { regions, partial } => {
                assert_eq!(regions.len(), 1);
                assert!(regions[0].description.contains("function_item"));
                let s = std::str::from_utf8(&partial).unwrap();
                assert!(s.contains("<<<<<<< ours"));
                assert!(s.contains(">>>>>>> theirs"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn rust_one_sided_edit_takes_that_side() {
        let base = "fn a() {}\n\nfn b() { let x = 1; }\n";
        let ours = "fn a() {}\n\nfn b() { let x = 1; }\n";
        let theirs = "fn a() {}\n\nfn b() { let x = 2; }\n";
        let result = run(Lang::Rust, base, ours, theirs);
        match result.status {
            MergeStatus::Merged { content, .. } => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains("let x = 2;"));
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn parse_failure_falls_through_to_not_applicable() {
        let bad = "fn a( {}\n"; // syntax error
        let ok = "fn a() {}\n";
        let result = run(Lang::Rust, ok, bad, ok);
        assert!(matches!(result.status, MergeStatus::NotApplicable));
    }

    #[test]
    fn cascade_routes_rust_files_to_tree_sitter_then_falls_through_on_parse_error() {
        let engine = CascadeEngine::default();
        // Parse error on ours → falls through to textual.
        let base = b"fn a() { 1 }\n";
        let ours = b"fn a( {} 1 }\n"; // broken
        let theirs = b"fn a() { 2 }\n";
        let res = engine.merge_file(Path::new("x.rs"), base, ours, theirs);
        // Textual is the fallback; it must not advertise itself as
        // tree-sitter:rust.
        assert_ne!(res.handler, "tree-sitter:rust");
    }

    #[test]
    fn python_disjoint_class_method_additions_merge() {
        let base = "def a():\n    return 1\n";
        let ours = "def a():\n    return 1\n\ndef b():\n    return 2\n";
        let theirs = "def a():\n    return 1\n\ndef c():\n    return 3\n";
        let result = run(Lang::Python, base, ours, theirs);
        match result.status {
            MergeStatus::Merged { content, .. } => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains("def a"));
                assert!(s.contains("def b"));
                assert!(s.contains("def c"));
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn deletion_on_one_side_is_honoured() {
        let base = "fn a() {}\n\nfn b() {}\n";
        let ours = "fn a() {}\n";
        let theirs = "fn a() {}\n\nfn b() {}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        match result.status {
            MergeStatus::Merged { content, .. } => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains("fn a()"));
                assert!(!s.contains("fn b()"));
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn modify_vs_delete_is_a_conflict() {
        let base = "fn a() {}\n\nfn b() {}\n";
        let ours = "fn a() {}\n\nfn b() { 1 }\n";
        let theirs = "fn a() {}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        match result.status {
            MergeStatus::Conflict { regions, .. } => {
                assert!(regions.iter().any(|r| r.description.contains("modify-vs-delete")));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    // ---------- recursion ----------

    #[test]
    fn rust_impl_disjoint_method_additions_merge_via_recursion() {
        // The flat handler would mark this a top-level conflict because
        // both sides modified `impl Foo`. With recursion we descend into
        // the impl body and merge `fn b` and `fn c` as disjoint adds.
        let base = "impl Foo {\n    fn a(&self) {}\n}\n";
        let ours = "impl Foo {\n    fn a(&self) {}\n    fn b(&self) {}\n}\n";
        let theirs = "impl Foo {\n    fn a(&self) {}\n    fn c(&self) {}\n}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        match result.status {
            MergeStatus::Merged { content, notes } => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains("fn a("), "must keep existing method: {s}");
                assert!(s.contains("fn b("), "must keep ours-side addition: {s}");
                assert!(s.contains("fn c("), "must keep theirs-side addition: {s}");
                assert!(s.contains("impl Foo"), "must preserve outer header");
                assert!(
                    notes.iter().any(|n| n.message.contains("recursive descent")),
                    "merge note must record that recursion fired: {notes:?}"
                );
            }
            other => panic!("expected Merged (via recursion), got {other:?}"),
        }
    }

    #[test]
    fn rust_impl_concurrent_edits_to_same_method_keep_outer_conflict() {
        // Both sides edit fn a's body — the inner method bodies are
        // anonymous statements, no recoverable identity, so recursion
        // refuses and we get a clean outer-block conflict.
        let base = "impl Foo {\n    fn a(&self) { 1 }\n}\n";
        let ours = "impl Foo {\n    fn a(&self) { 2 }\n}\n";
        let theirs = "impl Foo {\n    fn a(&self) { 3 }\n}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        match result.status {
            MergeStatus::Conflict { regions, .. } => {
                assert!(
                    regions.iter().any(|r| r.description.contains("impl_item")
                        || r.description.contains("function_item")),
                    "expected outer-block conflict: {:?}",
                    regions
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn rust_impl_header_rename_and_body_add_does_not_silently_recurse() {
        // ours renames the impl header (Foo → Bar), theirs adds a method.
        // A naive recursion would pick up theirs's method into ours's
        // renamed impl, silently discarding the rename mismatch. We
        // require the outer frame to be identical, so this stays an
        // outer conflict.
        let base = "impl Foo {\n    fn a(&self) {}\n}\n";
        let ours = "impl Bar {\n    fn a(&self) {}\n}\n";
        let theirs = "impl Foo {\n    fn a(&self) {}\n    fn d(&self) {}\n}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        // Frames diverge → no recursion → outer-level conflict reported.
        assert!(matches!(result.status, MergeStatus::Conflict { .. }));
    }

    #[test]
    fn java_class_disjoint_method_additions_merge_via_recursion() {
        let base = "class Foo {\n    void a() {}\n}\n";
        let ours = "class Foo {\n    void a() {}\n    void b() {}\n}\n";
        let theirs = "class Foo {\n    void a() {}\n    void c() {}\n}\n";
        let result = run(Lang::Java, base, ours, theirs);
        match result.status {
            MergeStatus::Merged { content, .. } => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains("void a("));
                assert!(s.contains("void b("));
                assert!(s.contains("void c("));
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn javascript_class_disjoint_method_additions_merge_via_recursion() {
        let base = "class Foo {\n    a() { return 1; }\n}\n";
        let ours = "class Foo {\n    a() { return 1; }\n    b() { return 2; }\n}\n";
        let theirs = "class Foo {\n    a() { return 1; }\n    c() { return 3; }\n}\n";
        let result = run(Lang::JavaScript, base, ours, theirs);
        match result.status {
            MergeStatus::Merged { content, .. } => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains("a()"));
                assert!(s.contains("b()"));
                assert!(s.contains("c()"));
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn rust_recursion_preserves_inter_child_indentation() {
        // The splice should re-use ours's "    " indent between methods,
        // not just join with "\n\n". Otherwise the merged file is valid
        // but ugly enough to confuse downstream review.
        let base = "impl Foo {\n    fn a(&self) {}\n}\n";
        let ours = "impl Foo {\n    fn a(&self) {}\n    fn b(&self) {}\n}\n";
        let theirs = "impl Foo {\n    fn a(&self) {}\n    fn c(&self) {}\n}\n";
        let result = run(Lang::Rust, base, ours, theirs);
        match result.status {
            MergeStatus::Merged { content, .. } => {
                let s = std::str::from_utf8(&content).unwrap();
                // The added method should begin with the same 4-space
                // indent used for fn b in ours — i.e., the merged file
                // contains "    fn c", not "fn c" at column 0.
                assert!(
                    s.contains("    fn c"),
                    "indentation must match ours's body style: {s}"
                );
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }
}
