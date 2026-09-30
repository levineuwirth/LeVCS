//! Revision specs: `HEAD`, a branch, a full hex id or a unique hex prefix of a
//! commit or release, each optionally followed
//! by `~N` (first parent, N times) and `^N` (the Nth parent, 1-based; `^0`
//! is the commit itself). Suffixes chain: `HEAD~2^2`.

use std::path::Path;

use anyhow::{anyhow, bail, Result};

use levcs_core::object::ObjectType;
use levcs_core::refs::validate_ref_name;
use levcs_core::{Commit, ObjectId, Repository};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Step {
    /// Follow the first parent this many times.
    Ancestor(u32),
    /// Take the Nth parent (0 = stay).
    Parent(u32),
}

/// Split `spec` at its first `~` or `^`: the base, and the suffix text.
fn split_base(spec: &str) -> (&str, &str) {
    spec.split_at(spec.find(['~', '^']).unwrap_or(spec.len()))
}

/// Parse suffix text into steps. Every operator is checked before it is
/// consumed, so anything that is not `~` or `^` (or a digit run after one) is
/// an error rather than being read as some other operator.
fn parse_steps(spec: &str, suffix: &str) -> Result<Vec<Step>> {
    let mut rest = suffix;
    let mut steps = Vec::new();
    while let Some(c) = rest.chars().next() {
        let make: fn(u32) -> Step = match c {
            '~' => Step::Ancestor,
            '^' => Step::Parent,
            _ => bail!("invalid revision `{spec}`: unexpected `{c}` after the base"),
        };
        rest = &rest[1..]; // `~` and `^` are one byte
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let n = if digits == 0 {
            1
        } else {
            rest[..digits]
                .parse::<u32>()
                .map_err(|_| anyhow!("number too large in revision `{spec}`"))?
        };
        rest = &rest[digits..];
        steps.push(make(n));
    }
    Ok(steps)
}

fn split(spec: &str) -> Result<(&str, Vec<Step>)> {
    let (base, suffix) = split_base(spec);
    Ok((base, parse_steps(spec, suffix)?))
}

fn walk(
    start: ObjectId,
    steps: &[Step],
    mut parents_of: impl FnMut(ObjectId) -> Result<Vec<ObjectId>>,
) -> Result<ObjectId> {
    let mut id = start;
    for step in steps {
        match *step {
            Step::Ancestor(n) => {
                for _ in 0..n {
                    id = *parents_of(id)?
                        .first()
                        .ok_or_else(|| anyhow!("commit {id} has no parent"))?;
                }
            }
            Step::Parent(0) => {}
            Step::Parent(n) => {
                let ps = parents_of(id)?;
                id = *ps.get(n as usize - 1).ok_or_else(|| {
                    anyhow!(
                        "commit {id} has {} parent{}, no parent {n}",
                        ps.len(),
                        if ps.len() == 1 { "" } else { "s" }
                    )
                })?;
            }
        }
    }
    Ok(id)
}

/// Shortest hex prefix accepted. Short enough to type, long enough that a
/// handful of commits do not collide on it.
const MIN_PREFIX: usize = 4;

fn is_hex_prefix(s: &str) -> bool {
    (MIN_PREFIX..64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Commits and releases whose id starts with `prefix`. Blobs and trees are
/// not revisions, so a prefix never names one; a full 64-character id still
/// may (`construct` takes a tree).
fn revisions_with_prefix(repo: &Repository, prefix: &str) -> Result<Vec<ObjectId>> {
    let mut found = Vec::new();
    for id in repo.objects.ids_with_prefix(&prefix.to_ascii_lowercase())? {
        if matches!(
            repo.read_raw_object(id)?.object_type,
            ObjectType::Commit | ObjectType::Release
        ) {
            found.push(id);
        }
    }
    Ok(found)
}

fn resolve_prefix(repo: &Repository, prefix: &str) -> Result<Option<ObjectId>> {
    let mut found = revisions_with_prefix(repo, prefix)?;
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        n => {
            let list: Vec<String> = found
                .iter()
                .take(5)
                .map(|id| id.to_hex()[..12].to_string())
                .collect();
            bail!(
                "ambiguous revision `{prefix}` matches {n} objects ({}{}); use more characters",
                list.join(", "),
                if n > 5 { ", ..." } else { "" }
            )
        }
    }
}

/// Resolve the base of a spec: `HEAD`, a branch, a full hex id, or a hex
/// prefix. A branch wins over a prefix. `Ok(None)` means the text is none
/// of those.
fn resolve_base(repo: &Repository, base: &str) -> Result<Option<ObjectId>> {
    if base == "HEAD" {
        return repo
            .refs
            .resolve_head()?
            .map(Some)
            .ok_or_else(|| anyhow!("HEAD has no commits"));
    }
    // Text that is not a legal ref name (`./notes`, `../x`, `/abs`) is a path
    // or nothing, never a branch, so it must not reach the ref lookup, which
    // rejects it with an error instead of a miss.
    let name = format!("refs/branches/{base}");
    if validate_ref_name(&name).is_ok() {
        if let Some(id) = repo.refs.read(&name)? {
            return Ok(Some(id));
        }
    }
    if let Ok(id) = ObjectId::from_hex(base) {
        return Ok(Some(id));
    }
    if is_hex_prefix(base) {
        return resolve_prefix(repo, base);
    }
    Ok(None)
}

fn walk_repo(repo: &Repository, base: ObjectId, steps: &[Step]) -> Result<ObjectId> {
    walk(base, steps, |id| {
        Ok(Commit::from_signed(&repo.read_signed(id)?)?.parents)
    })
}

/// Resolve `spec` to an object id, or fail with a message naming it.
pub fn resolve_rev(repo: &Repository, spec: &str) -> Result<ObjectId> {
    let (base, steps) = split(spec)?;
    let id =
        resolve_base(repo, base)?.ok_or_else(|| anyhow!("unknown branch or commit: {base}"))?;
    walk_repo(repo, id, &steps)
}

/// For positionals that may be a revision *or* a path (`diff`, `construct`).
/// `Ok(None)` means "treat as a path". A bare branch name stays a path, and
/// so does a suffixed name whose base is not a ref (`notes~`, an editor
/// backup); once the base resolves, a bad suffix is an error.
pub fn try_resolve_rev(repo: &Repository, spec: &str) -> Result<Option<ObjectId>> {
    let (base, suffix) = split_base(spec);
    let bare = suffix.is_empty();
    let is_head = base == "HEAD";
    let is_hex = ObjectId::from_hex(base).is_ok();
    let is_prefix = is_hex_prefix(base);
    if bare && !is_head && !is_hex && !is_prefix {
        return Ok(None);
    }
    let resolved = resolve_base(repo, base)?;
    if bare && is_prefix && !is_hex {
        // A bare run of hex digits is also a plausible file name. Only the
        // collision is an error; a miss is simply a path.
        if resolved.is_some() && Path::new(spec).exists() {
            bail!("`{spec}` is both a revision prefix and a path; write ./{spec} for the path");
        }
    }
    match resolved {
        // The base is a real revision, so a malformed suffix is the user's
        // mistake and is reported, not quietly reinterpreted as a path.
        Some(id) => walk_repo(repo, id, &parse_steps(spec, suffix)?).map(Some),
        None if bare && (is_head || is_hex) => bail!("unknown commit: {spec}"),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ObjectId {
        ObjectId([n; 32])
    }

    #[test]
    fn splits_suffixes() {
        assert_eq!(split("HEAD").unwrap(), ("HEAD", vec![]));
        assert_eq!(split("HEAD~").unwrap(), ("HEAD", vec![Step::Ancestor(1)]));
        assert_eq!(
            split("main~3^2~").unwrap(),
            (
                "main",
                vec![Step::Ancestor(3), Step::Parent(2), Step::Ancestor(1)]
            )
        );
        assert_eq!(split("x^0").unwrap().1, vec![Step::Parent(0)]);
        assert!(split("HEAD~99999999999").is_err());
    }

    #[test]
    fn rejects_malformed_suffixes_without_panicking() {
        for bad in [
            "HEAD~0x0", "HEAD~x", "HEAD~0é", "HEAD^é", "HEAD~1 ", "HEAD~~x",
        ] {
            assert!(split(bad).is_err(), "{bad} should be rejected");
        }
    }

    // 3 -> 2 -> 1, and 3 also has second parent 9.
    fn parents(i: ObjectId) -> Result<Vec<ObjectId>> {
        Ok(match i.0[0] {
            3 => vec![id(2), id(9)],
            2 => vec![id(1)],
            _ => vec![],
        })
    }

    #[test]
    fn walks_first_and_nth_parent() {
        assert_eq!(walk(id(3), &[Step::Ancestor(2)], parents).unwrap(), id(1));
        assert_eq!(walk(id(3), &[Step::Parent(2)], parents).unwrap(), id(9));
        assert_eq!(walk(id(3), &[Step::Parent(0)], parents).unwrap(), id(3));
        assert_eq!(
            walk(id(3), &[Step::Ancestor(1), Step::Parent(1)], parents).unwrap(),
            id(1)
        );
    }

    #[test]
    fn walk_errors_name_the_problem() {
        let e = walk(id(3), &[Step::Ancestor(3)], parents).unwrap_err();
        assert!(e.to_string().contains("has no parent"), "{e}");
        let e = walk(id(2), &[Step::Parent(2)], parents).unwrap_err();
        assert!(e.to_string().contains("has 1 parent, no parent 2"), "{e}");
    }
}
