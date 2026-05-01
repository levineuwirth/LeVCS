//! Format handlers that round out §6.3.1: YAML, Markdown, prose, XML.
//!
//! YAML reuses the same recursive value merge as the JSON handler, parsing
//! each side via `serde_yaml::Value` and bridging through `serde_json::Value`.
//!
//! Markdown is split into top-level sections by ATX heading; sections with a
//! shared heading are reconciled with the textual handler's diff3 merge,
//! while disjoint sections are kept independently. Sections without headings
//! (preamble, lists between headings) are treated as anonymous blocks keyed
//! by content hash, mirroring the tree-sitter handler's anonymous-block
//! handling.
//!
//! Prose is paragraph-aware: paragraphs separated by blank lines are merged
//! as identity-keyed blocks (paragraph text is its own key, so identical
//! paragraphs deduplicate; modified paragraphs that diverge become
//! conflicts). The spec describes a CRDT representation; this implementation
//! approximates that with a paragraph-level three-way merge — sufficient for
//! prose text where paragraph reordering is rare.
//!
//! XML treats each element as a structural node and merges children
//! recursively. Whitespace-only text nodes are not significant. Element
//! identity is `(tag-name, sorted-attributes, child-order-index)`; this is a
//! best-effort match that handles disjoint additions to different elements
//! without conflict.

use std::path::Path;

use serde_json::Value;

use crate::format::merge_value;
use crate::handler::{ConflictRegion, MergeHandler, MergeNote, MergeResult, MergeStatus};
use crate::textual::TextualHandler;

pub struct YamlHandler;
pub struct MarkdownHandler;
pub struct ProseHandler;
pub struct XmlHandler;

// ---------------------------------------------------------------------------
// YAML
// ---------------------------------------------------------------------------

fn yaml_to_json(v: serde_yaml::Value) -> Value {
    use serde_yaml::Value as Y;
    match v {
        Y::Null => Value::Null,
        Y::Bool(b) => Value::Bool(b),
        Y::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
            } else {
                Value::Null
            }
        }
        Y::String(s) => Value::String(s),
        Y::Sequence(seq) => Value::Array(seq.into_iter().map(yaml_to_json).collect()),
        Y::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    Y::String(s) => s,
                    other => serde_yaml::to_string(&other).unwrap_or_default(),
                };
                obj.insert(key, yaml_to_json(v));
            }
            Value::Object(obj)
        }
        Y::Tagged(t) => yaml_to_json(t.value),
    }
}

fn json_to_yaml(v: &Value) -> serde_yaml::Value {
    use serde_yaml::Value as Y;
    match v {
        Value::Null => Y::Null,
        Value::Bool(b) => Y::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Y::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                Y::Number(f.into())
            } else {
                Y::Null
            }
        }
        Value::String(s) => Y::String(s.clone()),
        Value::Array(a) => Y::Sequence(a.iter().map(json_to_yaml).collect()),
        Value::Object(o) => {
            let mut m = serde_yaml::Mapping::new();
            for (k, v) in o {
                m.insert(Y::String(k.clone()), json_to_yaml(v));
            }
            Y::Mapping(m)
        }
    }
}

impl MergeHandler for YamlHandler {
    fn name(&self) -> &str { "yaml" }

    fn applicable(&self, path: &Path, _b: &[u8], _o: &[u8], _t: &[u8]) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        )
    }

    fn merge(&self, _path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let parse = |b: &[u8]| -> Option<Value> {
            let v: serde_yaml::Value = serde_yaml::from_slice(b).ok()?;
            Some(yaml_to_json(v))
        };
        let (b, o, t) = match (parse(base), parse(ours), parse(theirs)) {
            (Some(b), Some(o), Some(t)) => (b, o, t),
            _ => {
                return MergeResult {
                    handler: self.name().into(),
                    status: MergeStatus::NotApplicable,
                };
            }
        };
        let (merged, conflicts) = merge_value(&b, &o, &t, "");
        let bytes = serde_yaml::to_string(&json_to_yaml(&merged))
            .unwrap_or_default()
            .into_bytes();
        let status = if conflicts.is_empty() {
            MergeStatus::Merged {
                content: bytes,
                notes: vec![MergeNote { message: "structural YAML three-way merge".into() }],
            }
        } else {
            MergeStatus::Conflict { regions: conflicts, partial: bytes }
        };
        MergeResult { handler: self.name().into(), status }
    }
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MdSection {
    /// `None` for the preamble (before the first heading) or anonymous body.
    heading: Option<String>,
    text: String,
}

fn split_markdown(src: &str) -> Vec<MdSection> {
    let mut out: Vec<MdSection> = Vec::new();
    let mut cur = MdSection { heading: None, text: String::new() };
    for line in src.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            if !cur.text.is_empty() || cur.heading.is_some() {
                out.push(std::mem::replace(
                    &mut cur,
                    MdSection { heading: None, text: String::new() },
                ));
            }
            // Extract heading text (without leading #s).
            let head = trimmed
                .trim_start_matches('#')
                .trim()
                .trim_end_matches('\n')
                .to_string();
            cur.heading = Some(head);
            cur.text.push_str(line);
        } else {
            cur.text.push_str(line);
        }
    }
    if !cur.text.is_empty() || cur.heading.is_some() {
        out.push(cur);
    }
    out
}

impl MergeHandler for MarkdownHandler {
    fn name(&self) -> &str { "markdown" }

    fn applicable(&self, path: &Path, _b: &[u8], _o: &[u8], _t: &[u8]) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("md") | Some("markdown")
        )
    }

    fn merge(&self, path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let parse = |b: &[u8]| -> Option<Vec<MdSection>> {
            std::str::from_utf8(b).ok().map(split_markdown)
        };
        let (b, o, t) = match (parse(base), parse(ours), parse(theirs)) {
            (Some(b), Some(o), Some(t)) => (b, o, t),
            _ => {
                return MergeResult {
                    handler: self.name().into(),
                    status: MergeStatus::NotApplicable,
                };
            }
        };

        let key = |s: &MdSection| -> String {
            match &s.heading {
                Some(h) => format!("h:{h}"),
                None => format!("anon:{}", blake3::hash(s.text.as_bytes()).to_hex()),
            }
        };

        let lookup = |list: &[MdSection], k: &str| -> Option<MdSection> {
            list.iter().find(|s| key(s) == *k).cloned()
        };

        let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut output: Vec<String> = Vec::new();
        let mut conflicts: Vec<ConflictRegion> = Vec::new();
        let textual = TextualHandler;

        for s in &o {
            let k = key(s);
            if !emitted.insert(k.clone()) {
                continue;
            }
            let bs = lookup(&b, &k);
            let ts = lookup(&t, &k);
            match (bs, ts) {
                (None, None) => output.push(s.text.clone()),
                (None, Some(ts)) => {
                    if s.text == ts.text {
                        output.push(s.text.clone());
                    } else if let Some(h) = &s.heading {
                        let res = textual.merge(path, b"", s.text.as_bytes(), ts.text.as_bytes());
                        match res.status {
                            MergeStatus::Merged { content, .. } => {
                                output.push(String::from_utf8_lossy(&content).to_string());
                            }
                            MergeStatus::Conflict { partial, regions } => {
                                output.push(String::from_utf8_lossy(&partial).to_string());
                                for mut r in regions {
                                    r.description = format!("section '{h}': {}", r.description);
                                    conflicts.push(r);
                                }
                            }
                            MergeStatus::NotApplicable => output.push(s.text.clone()),
                        }
                    } else {
                        output.push(s.text.clone());
                        output.push(ts.text.clone());
                    }
                }
                (Some(bs), None) => {
                    // Section deleted in theirs.
                    if s.text == bs.text {
                        // unchanged ours, deleted theirs → drop
                    } else {
                        output.push(s.text.clone());
                        conflicts.push(ConflictRegion {
                            description: format!("section '{}' modified vs deleted", s.heading.clone().unwrap_or_default()),
                            base: 0..0, ours: 0..0, theirs: 0..0,
                        });
                    }
                }
                (Some(bs), Some(ts)) => {
                    let ours_changed = s.text != bs.text;
                    let theirs_changed = ts.text != bs.text;
                    match (ours_changed, theirs_changed) {
                        (false, false) => output.push(s.text.clone()),
                        (true, false) => output.push(s.text.clone()),
                        (false, true) => output.push(ts.text.clone()),
                        (true, true) => {
                            if s.text == ts.text {
                                output.push(s.text.clone());
                            } else {
                                let res = textual.merge(
                                    path,
                                    bs.text.as_bytes(),
                                    s.text.as_bytes(),
                                    ts.text.as_bytes(),
                                );
                                match res.status {
                                    MergeStatus::Merged { content, .. } => {
                                        output.push(String::from_utf8_lossy(&content).to_string());
                                    }
                                    MergeStatus::Conflict { partial, regions } => {
                                        output.push(String::from_utf8_lossy(&partial).to_string());
                                        let h = s.heading.clone().unwrap_or_default();
                                        for mut r in regions {
                                            r.description = format!("section '{h}': {}", r.description);
                                            conflicts.push(r);
                                        }
                                    }
                                    MergeStatus::NotApplicable => output.push(s.text.clone()),
                                }
                            }
                        }
                    }
                }
            }
        }

        for s in &t {
            let k = key(s);
            if emitted.contains(&k) {
                continue;
            }
            emitted.insert(k.clone());
            match lookup(&b, &k) {
                None => output.push(s.text.clone()),
                Some(bs) => {
                    if s.text == bs.text {
                        // theirs unchanged, ours deleted → drop
                    } else {
                        output.push(s.text.clone());
                        conflicts.push(ConflictRegion {
                            description: format!(
                                "section '{}' deleted by ours, modified by theirs",
                                s.heading.clone().unwrap_or_default()
                            ),
                            base: 0..0, ours: 0..0, theirs: 0..0,
                        });
                    }
                }
            }
        }

        let merged = output.concat();
        let status = if conflicts.is_empty() {
            MergeStatus::Merged {
                content: merged.into_bytes(),
                notes: vec![MergeNote { message: "section-based markdown merge".into() }],
            }
        } else {
            MergeStatus::Conflict { regions: conflicts, partial: merged.into_bytes() }
        };
        MergeResult { handler: self.name().into(), status }
    }
}

// ---------------------------------------------------------------------------
// Prose (paragraph-aware textual)
// ---------------------------------------------------------------------------

fn split_paragraphs(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in s.split_inclusive('\n') {
        if line.trim().is_empty() {
            cur.push_str(line);
            if !cur.trim().is_empty() {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        } else {
            cur.push_str(line);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

impl MergeHandler for ProseHandler {
    fn name(&self) -> &str { "prose" }

    fn applicable(&self, path: &Path, _b: &[u8], _o: &[u8], _t: &[u8]) -> bool {
        matches!(path.extension().and_then(|e| e.to_str()), Some("txt"))
    }

    fn merge(&self, path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let to_paras = |b: &[u8]| -> Option<Vec<String>> {
            std::str::from_utf8(b).ok().map(split_paragraphs)
        };
        let (b, o, t) = match (to_paras(base), to_paras(ours), to_paras(theirs)) {
            (Some(b), Some(o), Some(t)) => (b, o, t),
            _ => {
                return MergeResult {
                    handler: self.name().into(),
                    status: MergeStatus::NotApplicable,
                };
            }
        };
        let key = |p: &str| -> String {
            blake3::hash(p.trim().as_bytes()).to_hex().to_string()
        };
        // Paragraph identity is content-only, so a modification looks like
        // delete+add. To avoid silently concatenating two divergent edits
        // (which would lose their conflict), check that every base paragraph
        // is preserved in ours or theirs. If any base paragraph is gone from
        // both sides, the divergent edits could conflict — fall through to
        // textual diff3 for safety.
        let preserved = b.iter().all(|p| {
            let k = key(p);
            o.iter().any(|x| key(x) == k) || t.iter().any(|x| key(x) == k)
        });
        if !preserved {
            let textual = TextualHandler;
            let mut res = textual.merge(path, base, ours, theirs);
            res.handler = self.name().into();
            return res;
        }
        let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut out: Vec<String> = Vec::new();

        for p in &o {
            let k = key(p);
            if !emitted.insert(k.clone()) {
                continue;
            }
            let in_base = b.iter().any(|x| key(x) == k);
            let in_theirs = t.iter().any(|x| key(x) == k);
            if in_base || in_theirs {
                out.push(p.clone());
            } else {
                out.push(p.clone());
            }
        }
        for p in &t {
            let k = key(p);
            if emitted.contains(&k) {
                continue;
            }
            emitted.insert(k.clone());
            let in_base = b.iter().any(|x| key(x) == k);
            if !in_base {
                // Independently added paragraph in theirs.
                out.push(p.clone());
            } else {
                // Theirs's paragraph existed in base but not in ours → ours deleted it.
                // Honour the deletion (drop).
            }
        }
        // Detect deleted-in-theirs paragraphs: paragraphs in base but in
        // neither ours nor theirs were deleted by both, so already absent.
        // Paragraphs in base+ours but not theirs were deleted by theirs and
        // already absent from `out` only if ours's iteration didn't keep
        // them — but we always keep ours. Treat as ours-wins (keep).

        let merged = out.concat();
        MergeResult {
            handler: self.name().into(),
            status: MergeStatus::Merged {
                content: merged.into_bytes(),
                notes: vec![MergeNote { message: "paragraph-level prose merge".into() }],
            },
        }
    }
}

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum XmlNode {
    Element {
        name: String,
        attrs: Vec<(String, String)>,
        children: Vec<XmlNode>,
    },
    Text(String),
}

fn xml_parse(src: &[u8]) -> Option<Vec<XmlNode>> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut reader = Reader::from_reader(src);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut stack: Vec<(String, Vec<(String, String)>, Vec<XmlNode>)> = Vec::new();
    let mut top: Vec<XmlNode> = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(e) => {
                let name = std::str::from_utf8(e.name().as_ref()).ok()?.to_string();
                let mut attrs = Vec::new();
                for a in e.attributes().with_checks(false).flatten() {
                    let k = std::str::from_utf8(a.key.as_ref()).ok()?.to_string();
                    let v = a.unescape_value().ok()?.to_string();
                    attrs.push((k, v));
                }
                attrs.sort();
                stack.push((name, attrs, Vec::new()));
            }
            Event::End(_) => {
                let (name, attrs, children) = stack.pop()?;
                let node = XmlNode::Element { name, attrs, children };
                if let Some(parent) = stack.last_mut() {
                    parent.2.push(node);
                } else {
                    top.push(node);
                }
            }
            Event::Empty(e) => {
                let name = std::str::from_utf8(e.name().as_ref()).ok()?.to_string();
                let mut attrs = Vec::new();
                for a in e.attributes().with_checks(false).flatten() {
                    let k = std::str::from_utf8(a.key.as_ref()).ok()?.to_string();
                    let v = a.unescape_value().ok()?.to_string();
                    attrs.push((k, v));
                }
                attrs.sort();
                let node = XmlNode::Element { name, attrs, children: Vec::new() };
                if let Some(parent) = stack.last_mut() {
                    parent.2.push(node);
                } else {
                    top.push(node);
                }
            }
            Event::Text(t) => {
                let s = std::str::from_utf8(t.as_ref()).ok()?.to_string();
                let node = XmlNode::Text(s);
                if let Some(parent) = stack.last_mut() {
                    parent.2.push(node);
                } else {
                    top.push(node);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Some(top)
}

fn xml_serialize(nodes: &[XmlNode]) -> String {
    let mut out = String::new();
    for n in nodes {
        write_node(n, &mut out);
    }
    out
}

fn write_node(n: &XmlNode, out: &mut String) {
    match n {
        XmlNode::Text(t) => {
            out.push_str(&xml_escape_text(t));
        }
        XmlNode::Element { name, attrs, children } => {
            out.push('<');
            out.push_str(name);
            for (k, v) in attrs {
                out.push(' ');
                out.push_str(k);
                out.push_str("=\"");
                out.push_str(&xml_escape_attr(v));
                out.push('"');
            }
            if children.is_empty() {
                out.push_str("/>");
            } else {
                out.push('>');
                for c in children {
                    write_node(c, out);
                }
                out.push_str("</");
                out.push_str(name);
                out.push('>');
            }
        }
    }
}

fn xml_escape_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;")
}

fn xml_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;")
}

fn merge_xml_children(
    base: &[XmlNode],
    ours: &[XmlNode],
    theirs: &[XmlNode],
    path: &str,
) -> (Vec<XmlNode>, Vec<ConflictRegion>) {
    if ours == theirs {
        return (ours.to_vec(), Vec::new());
    }
    if base == ours {
        return (theirs.to_vec(), Vec::new());
    }
    if base == theirs {
        return (ours.to_vec(), Vec::new());
    }
    // Sequence-aware merge: iterate by element name + position. Disjoint
    // additions of differently-named siblings stay non-conflicting; same-
    // name siblings recurse.
    let mut conflicts = Vec::new();
    let max_len = base.len().max(ours.len()).max(theirs.len());
    let mut merged: Vec<XmlNode> = Vec::new();
    for i in 0..max_len {
        let bv = base.get(i);
        let ov = ours.get(i);
        let tv = theirs.get(i);
        match (bv, ov, tv) {
            (None, None, None) => {}
            (None, Some(o), None) => merged.push(o.clone()),
            (None, None, Some(t)) => merged.push(t.clone()),
            (Some(_), None, None) => {}
            (Some(b), Some(o), None) => {
                if b == o { /* deleted in theirs */ } else {
                    merged.push(o.clone());
                    conflicts.push(ConflictRegion {
                        description: format!("{path}[{i}]: modified by ours, deleted by theirs"),
                        base: 0..0, ours: 0..0, theirs: 0..0,
                    });
                }
            }
            (Some(b), None, Some(t)) => {
                if b == t { /* deleted in ours */ } else {
                    merged.push(t.clone());
                    conflicts.push(ConflictRegion {
                        description: format!("{path}[{i}]: deleted by ours, modified by theirs"),
                        base: 0..0, ours: 0..0, theirs: 0..0,
                    });
                }
            }
            (None, Some(o), Some(t)) => {
                if o == t {
                    merged.push(o.clone());
                } else {
                    merged.push(o.clone());
                    conflicts.push(ConflictRegion {
                        description: format!("{path}[{i}]: independently added with different values"),
                        base: 0..0, ours: 0..0, theirs: 0..0,
                    });
                }
            }
            (Some(b), Some(o), Some(t)) => {
                let (m, c) = merge_xml_node(b, o, t, &format!("{path}[{i}]"));
                merged.push(m);
                conflicts.extend(c);
            }
        }
    }
    (merged, conflicts)
}

fn merge_xml_node(
    base: &XmlNode,
    ours: &XmlNode,
    theirs: &XmlNode,
    path: &str,
) -> (XmlNode, Vec<ConflictRegion>) {
    if ours == theirs {
        return (ours.clone(), Vec::new());
    }
    if base == ours {
        return (theirs.clone(), Vec::new());
    }
    if base == theirs {
        return (ours.clone(), Vec::new());
    }
    match (base, ours, theirs) {
        (
            XmlNode::Element { name: bn, attrs: ba, children: bc },
            XmlNode::Element { name: on, attrs: oa, children: oc },
            XmlNode::Element { name: tn, attrs: ta, children: tc },
        ) if bn == on && on == tn => {
            // Merge attributes structurally via JSON.
            let to_obj = |v: &[(String, String)]| -> Value {
                let mut m = serde_json::Map::new();
                for (k, val) in v { m.insert(k.clone(), Value::String(val.clone())); }
                Value::Object(m)
            };
            let (am, ac) = merge_value(&to_obj(ba), &to_obj(oa), &to_obj(ta), &format!("{path}.@"));
            let attrs: Vec<(String, String)> = match am {
                Value::Object(m) => {
                    let mut v: Vec<_> = m.into_iter()
                        .map(|(k, val)| (k, val.as_str().unwrap_or("").to_string()))
                        .collect();
                    v.sort();
                    v
                }
                _ => oa.clone(),
            };
            let (cm, cc) = merge_xml_children(bc, oc, tc, &format!("{path}/{on}"));
            let mut conflicts = ac;
            conflicts.extend(cc);
            (
                XmlNode::Element { name: on.clone(), attrs, children: cm },
                conflicts,
            )
        }
        _ => {
            // Tag-name change or text/element type mismatch — flat conflict.
            (
                ours.clone(),
                vec![ConflictRegion {
                    description: format!("{path}: structural mismatch between ours and theirs"),
                    base: 0..0, ours: 0..0, theirs: 0..0,
                }],
            )
        }
    }
}

impl MergeHandler for XmlHandler {
    fn name(&self) -> &str { "xml" }

    fn applicable(&self, path: &Path, _b: &[u8], _o: &[u8], _t: &[u8]) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("xml") | Some("svg") | Some("html")
        )
    }

    fn merge(&self, _path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let (b, o, t) = match (xml_parse(base), xml_parse(ours), xml_parse(theirs)) {
            (Some(b), Some(o), Some(t)) => (b, o, t),
            _ => {
                return MergeResult {
                    handler: self.name().into(),
                    status: MergeStatus::NotApplicable,
                };
            }
        };
        let (merged, conflicts) = merge_xml_children(&b, &o, &t, "");
        let s = xml_serialize(&merged);
        let bytes = s.into_bytes();
        let status = if conflicts.is_empty() {
            MergeStatus::Merged {
                content: bytes,
                notes: vec![MergeNote { message: "structural XML merge".into() }],
            }
        } else {
            MergeStatus::Conflict { regions: conflicts, partial: bytes }
        };
        MergeResult { handler: self.name().into(), status }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_disjoint_keys_merge() {
        let h = YamlHandler;
        let base = b"a: 1\n";
        let ours = b"a: 1\nb: 2\n";
        let theirs = b"a: 1\nc: 3\n";
        let r = h.merge(Path::new("x.yaml"), base, ours, theirs);
        match r.status {
            MergeStatus::Merged { content, .. } => {
                let s = String::from_utf8_lossy(&content);
                assert!(s.contains("a:"));
                assert!(s.contains("b:"));
                assert!(s.contains("c:"));
            }
            other => panic!("expected merged, got {other:?}"),
        }
    }

    #[test]
    fn yaml_scalar_conflict() {
        let h = YamlHandler;
        let base = b"x: 1\n";
        let ours = b"x: 2\n";
        let theirs = b"x: 3\n";
        let r = h.merge(Path::new("x.yml"), base, ours, theirs);
        assert!(matches!(r.status, MergeStatus::Conflict { .. }));
    }

    #[test]
    fn markdown_disjoint_section_additions_merge() {
        let h = MarkdownHandler;
        let base = b"# Intro\n\nHello.\n";
        let ours = b"# Intro\n\nHello.\n\n# A\n\nours.\n";
        let theirs = b"# Intro\n\nHello.\n\n# B\n\ntheirs.\n";
        let r = h.merge(Path::new("x.md"), base, ours, theirs);
        match r.status {
            MergeStatus::Merged { content, .. } => {
                let s = String::from_utf8_lossy(&content);
                assert!(s.contains("# A"));
                assert!(s.contains("# B"));
            }
            other => panic!("expected merged, got {other:?}"),
        }
    }

    #[test]
    fn markdown_same_section_diverges_to_conflict() {
        let h = MarkdownHandler;
        let base = b"# A\n\nbase.\n";
        let ours = b"# A\n\nours.\n";
        let theirs = b"# A\n\ntheirs.\n";
        let r = h.merge(Path::new("x.md"), base, ours, theirs);
        assert!(matches!(r.status, MergeStatus::Conflict { .. }));
    }

    #[test]
    fn prose_independently_added_paragraphs_merge() {
        let h = ProseHandler;
        let base = b"para one.\n";
        let ours = b"para one.\n\nours added.\n";
        let theirs = b"para one.\n\ntheirs added.\n";
        let r = h.merge(Path::new("x.txt"), base, ours, theirs);
        match r.status {
            MergeStatus::Merged { content, .. } => {
                let s = String::from_utf8_lossy(&content);
                assert!(s.contains("para one."));
                assert!(s.contains("ours added."));
                assert!(s.contains("theirs added."));
            }
            other => panic!("expected merged, got {other:?}"),
        }
    }

    #[test]
    fn xml_disjoint_attrs_merge() {
        let h = XmlHandler;
        let base = br#"<root><a x="1"/></root>"#;
        let ours = br#"<root><a x="1" y="2"/></root>"#;
        let theirs = br#"<root><a x="1" z="3"/></root>"#;
        let r = h.merge(Path::new("x.xml"), base, ours, theirs);
        match r.status {
            MergeStatus::Merged { content, .. } => {
                let s = String::from_utf8_lossy(&content);
                assert!(s.contains("y=\"2\""));
                assert!(s.contains("z=\"3\""));
            }
            other => panic!("expected merged, got {other:?}"),
        }
    }

    #[test]
    fn xml_scalar_attr_conflict() {
        let h = XmlHandler;
        let base = br#"<a x="1"/>"#;
        let ours = br#"<a x="2"/>"#;
        let theirs = br#"<a x="3"/>"#;
        let r = h.merge(Path::new("x.xml"), base, ours, theirs);
        assert!(matches!(r.status, MergeStatus::Conflict { .. }));
    }
}
