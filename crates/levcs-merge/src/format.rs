//! Format-aware handlers: JSON, TOML, YAML.
//!
//! Each handler parses base/ours/theirs as the named structured format and
//! performs a three-way merge over the parsed value. JSON/TOML/YAML are
//! merged via the same recursive `merge_value` logic on `serde_json::Value`,
//! since that type can losslessly represent all three for our purposes.

use std::path::Path;

use serde_json::Value;

use crate::handler::{ConflictRegion, MergeHandler, MergeNote, MergeResult, MergeStatus};

pub struct JsonHandler;
pub struct TomlHandler;

impl MergeHandler for JsonHandler {
    fn name(&self) -> &str { "json" }
    fn applicable(&self, path: &Path, _b: &[u8], _o: &[u8], _t: &[u8]) -> bool {
        path.extension().and_then(|e| e.to_str()) == Some("json")
    }
    fn merge(&self, _path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let try_parse = |b: &[u8]| -> Option<Value> { serde_json::from_slice(b).ok() };
        let (b, o, t) = match (try_parse(base), try_parse(ours), try_parse(theirs)) {
            (Some(b), Some(o), Some(t)) => (b, o, t),
            _ => {
                return MergeResult {
                    handler: self.name().into(),
                    status: MergeStatus::NotApplicable,
                };
            }
        };
        let (merged, conflicts) = merge_value(&b, &o, &t, "");
        let bytes = serde_json::to_vec_pretty(&merged).unwrap_or_default();
        let status = if conflicts.is_empty() {
            MergeStatus::Merged {
                content: bytes,
                notes: vec![MergeNote { message: "structural JSON three-way merge".into() }],
            }
        } else {
            MergeStatus::Conflict { regions: conflicts, partial: bytes }
        };
        MergeResult { handler: self.name().into(), status }
    }
}

impl MergeHandler for TomlHandler {
    fn name(&self) -> &str { "toml" }
    fn applicable(&self, path: &Path, _b: &[u8], _o: &[u8], _t: &[u8]) -> bool {
        path.extension().and_then(|e| e.to_str()) == Some("toml")
    }
    fn merge(&self, _path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let try_parse = |b: &[u8]| -> Option<Value> {
            let s = std::str::from_utf8(b).ok()?;
            let t: toml::Value = toml::from_str(s).ok()?;
            toml_to_json(&t).into()
        };
        let (b, o, t) = match (try_parse(base), try_parse(ours), try_parse(theirs)) {
            (Some(b), Some(o), Some(t)) => (b, o, t),
            _ => {
                return MergeResult {
                    handler: self.name().into(),
                    status: MergeStatus::NotApplicable,
                };
            }
        };
        let (merged, conflicts) = merge_value(&b, &o, &t, "");
        let toml_value = json_to_toml(&merged);
        let s = toml::to_string_pretty(&toml_value).unwrap_or_default();
        let bytes = s.into_bytes();
        let status = if conflicts.is_empty() {
            MergeStatus::Merged {
                content: bytes,
                notes: vec![MergeNote { message: "structural TOML three-way merge".into() }],
            }
        } else {
            MergeStatus::Conflict { regions: conflicts, partial: bytes }
        };
        MergeResult { handler: self.name().into(), status }
    }
}

fn toml_to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::from(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(arr) => Value::Array(arr.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => {
            let mut m = serde_json::Map::new();
            for (k, v) in t {
                m.insert(k.clone(), toml_to_json(v));
            }
            Value::Object(m)
        }
    }
}

fn json_to_toml(v: &Value) -> toml::Value {
    match v {
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::String(n.to_string())
            }
        }
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::Null => toml::Value::String(String::new()),
        Value::Array(arr) => toml::Value::Array(arr.iter().map(json_to_toml).collect()),
        Value::Object(o) => {
            let mut t = toml::map::Map::new();
            for (k, v) in o {
                t.insert(k.clone(), json_to_toml(v));
            }
            toml::Value::Table(t)
        }
    }
}

/// Recursive structural merge over `serde_json::Value`. Reused by the YAML
/// handler (which converts via `serde_yaml::Value`).
pub fn merge_value(
    base: &Value,
    ours: &Value,
    theirs: &Value,
    path: &str,
) -> (Value, Vec<ConflictRegion>) {
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
        (Value::Object(b), Value::Object(o), Value::Object(t)) => {
            let mut merged = serde_json::Map::new();
            let mut conflicts = Vec::new();
            let mut keys: std::collections::BTreeSet<&String> = b.keys().collect();
            keys.extend(o.keys());
            keys.extend(t.keys());
            for k in keys {
                let bv = b.get(k);
                let ov = o.get(k);
                let tv = t.get(k);
                let sub_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match (bv, ov, tv) {
                    (None, None, None) => {}
                    (None, Some(o), None) => { merged.insert(k.clone(), o.clone()); }
                    (None, None, Some(t)) => { merged.insert(k.clone(), t.clone()); }
                    (Some(b), Some(o), None) => {
                        if b == o {
                            // theirs deleted; ours unchanged → delete.
                        } else {
                            // ours modified, theirs deleted → conflict (keep ours).
                            merged.insert(k.clone(), o.clone());
                            conflicts.push(ConflictRegion {
                                description: format!("{sub_path}: modified by ours, deleted by theirs"),
                                base: 0..0, ours: 0..0, theirs: 0..0,
                            });
                        }
                    }
                    (Some(b), None, Some(t)) => {
                        if b == t {
                            // ours deleted; theirs unchanged → delete.
                        } else {
                            merged.insert(k.clone(), t.clone());
                            conflicts.push(ConflictRegion {
                                description: format!("{sub_path}: deleted by ours, modified by theirs"),
                                base: 0..0, ours: 0..0, theirs: 0..0,
                            });
                        }
                    }
                    (Some(b), Some(o), Some(t)) => {
                        let (sub, c) = merge_value(b, o, t, &sub_path);
                        merged.insert(k.clone(), sub);
                        conflicts.extend(c);
                    }
                    (None, Some(o), Some(t)) => {
                        if o == t {
                            merged.insert(k.clone(), o.clone());
                        } else {
                            merged.insert(k.clone(), o.clone());
                            conflicts.push(ConflictRegion {
                                description: format!("{sub_path}: independently added with different values"),
                                base: 0..0, ours: 0..0, theirs: 0..0,
                            });
                        }
                    }
                    (Some(_b), None, None) => { /* both deleted, drop */ }
                }
            }
            (Value::Object(merged), conflicts)
        }
        (Value::Array(_b), Value::Array(o), Value::Array(t)) => {
            // Concatenate ours then theirs additions, preserving the spec's
            // "independent additions are merged" guidance for primitive
            // arrays (with deduplication).
            let mut merged: Vec<Value> = o.clone();
            for v in t {
                if !merged.contains(v) {
                    merged.push(v.clone());
                }
            }
            (Value::Array(merged), Vec::new())
        }
        _ => {
            // Scalar conflict.
            let conflict = ConflictRegion {
                description: format!("{path}: divergent scalar modifications"),
                base: 0..0, ours: 0..0, theirs: 0..0,
            };
            (ours.clone(), vec![conflict])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_object_merge_disjoint() {
        let h = JsonHandler;
        let base = br#"{"a":1}"#;
        let ours = br#"{"a":1,"b":2}"#;
        let theirs = br#"{"a":1,"c":3}"#;
        let r = h.merge(Path::new("x.json"), base, ours, theirs);
        match r.status {
            MergeStatus::Merged { content, .. } => {
                let v: Value = serde_json::from_slice(&content).unwrap();
                assert_eq!(v["a"], 1);
                assert_eq!(v["b"], 2);
                assert_eq!(v["c"], 3);
            }
            other => panic!("expected merged, got {other:?}"),
        }
    }

    #[test]
    fn json_scalar_conflict() {
        let h = JsonHandler;
        let base = br#"{"a":1}"#;
        let ours = br#"{"a":2}"#;
        let theirs = br#"{"a":3}"#;
        let r = h.merge(Path::new("x.json"), base, ours, theirs);
        match r.status {
            MergeStatus::Conflict { regions, .. } => assert_eq!(regions.len(), 1),
            _ => panic!("expected conflict"),
        }
    }
}
