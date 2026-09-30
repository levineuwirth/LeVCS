//! Revision specs: `HEAD`, a branch, a full hex id, each optionally followed
//! by `~N` (first parent, N times) and `^N` (the Nth parent, 1-based; `^0`
//! is the commit itself). Suffixes chain: `HEAD~2^2`.

use anyhow::{anyhow, bail, Result};

use levcs_core::{Commit, ObjectId, Repository};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Step {
    /// Follow the first parent this many times.
    Ancestor(u32),
    /// Take the Nth parent (0 = stay).
    Parent(u32),
}

/// Split `spec` into its base and suffix steps. The base is everything
/// before the first `~` or `^`.
fn split(spec: &str) -> Result<(&str, Vec<Step>)> {
    let at = spec.find(['~', '^']).unwrap_or(spec.len());
    let (base, mut rest) = spec.split_at(at);
    let mut steps = Vec::new();
    while let Some(c) = rest.chars().next() {
        rest = &rest[1..];
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let n = if digits == 0 {
            1
        } else {
            rest[..digits]
                .parse::<u32>()
                .map_err(|_| anyhow!("number too large in revision `{spec}`"))?
        };
        rest = &rest[digits..];
        steps.push(if c == '~' {
            Step::Ancestor(n)
        } else {
            Step::Parent(n)
        });
    }
    Ok((base, steps))
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

/// Resolve the base of a spec: `HEAD`, a branch, or a full hex id.
/// `Ok(None)` means the text is not any of those.
fn resolve_base(repo: &Repository, base: &str) -> Result<Option<ObjectId>> {
    if base == "HEAD" {
        return repo
            .refs
            .resolve_head()?
            .map(Some)
            .ok_or_else(|| anyhow!("HEAD has no commits"));
    }
    if !base.is_empty() {
        if let Some(id) = repo.refs.read(&format!("refs/branches/{base}"))? {
            return Ok(Some(id));
        }
    }
    Ok(ObjectId::from_hex(base).ok())
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
    let Ok((base, steps)) = split(spec) else {
        return Ok(None);
    };
    let bare = steps.is_empty();
    let is_head = base == "HEAD";
    let is_hex = ObjectId::from_hex(base).is_ok();
    if bare && !is_head && !is_hex {
        return Ok(None);
    }
    match resolve_base(repo, base)? {
        Some(id) => walk_repo(repo, id, &steps).map(Some),
        None if bare => bail!("unknown commit: {spec}"),
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
