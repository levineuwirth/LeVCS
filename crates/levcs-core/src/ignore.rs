//! Minimal `.levcsignore` support: a list of glob patterns, evaluated against
//! repository-relative paths. Patterns starting with `/` are anchored to the
//! repo root; bare patterns match anywhere. Patterns prefixed with `!` are
//! negations (re-include).

use std::path::Path;

use glob::Pattern;

#[derive(Clone, Debug, Default)]
pub struct Ignore {
    rules: Vec<Rule>,
}

#[derive(Clone, Debug)]
struct Rule {
    pattern: Pattern,
    negate: bool,
    /// Anchored to repo root (true) or matches any directory (false).
    anchored: bool,
}

impl Ignore {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a `.levcsignore` file's contents.
    pub fn parse(text: &str) -> Self {
        let mut rules = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (negate, body) = if let Some(rest) = trimmed.strip_prefix('!') {
                (true, rest)
            } else {
                (false, trimmed)
            };
            let (anchored, body) = if let Some(rest) = body.strip_prefix('/') {
                (true, rest)
            } else {
                (false, body)
            };
            // Always include `.levcs/` itself in the ignored set.
            if let Ok(pattern) = Pattern::new(body) {
                rules.push(Rule {
                    pattern,
                    negate,
                    anchored,
                });
            }
        }
        // Always ignore `.levcs/`
        if let Ok(pattern) = Pattern::new(".levcs") {
            rules.insert(
                0,
                Rule {
                    pattern,
                    negate: false,
                    anchored: true,
                },
            );
        }
        if let Ok(pattern) = Pattern::new(".levcs/**") {
            rules.insert(
                0,
                Rule {
                    pattern,
                    negate: false,
                    anchored: true,
                },
            );
        }
        Self { rules }
    }

    pub fn is_ignored(&self, rel_path: &str) -> bool {
        let mut ignored = false;
        for r in &self.rules {
            let matched = if r.anchored {
                r.pattern.matches(rel_path)
            } else {
                // Match against any suffix path component sequence.
                r.pattern.matches(rel_path) || rel_path.split('/').any(|c| r.pattern.matches(c))
            };
            if matched {
                ignored = !r.negate;
            }
        }
        ignored
    }
}

/// Always-ignored paths regardless of `.levcsignore`: the repository's own
/// `.levcs`, and a nested repository's. Only the top level used to be
/// skipped, so a nested repository's metadata could be tracked and
/// committed, into a tree that checkout must refuse.
pub fn always_ignored(rel: &Path) -> bool {
    rel.components().any(|c| c.as_os_str() == ".levcs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotlevcs_always_ignored() {
        let ig = Ignore::empty();
        assert!(always_ignored(Path::new(".levcs")));
        assert!(always_ignored(Path::new(".levcs/objects")));
        assert!(always_ignored(Path::new("sub/.levcs/config")));
        assert!(!always_ignored(Path::new("src/main.rs")));
        assert!(!always_ignored(Path::new("src/.levcsignore")));
        let _ = ig;
    }

    #[test]
    fn negation() {
        let ig = Ignore::parse("*.log\n!keep.log\n");
        assert!(ig.is_ignored("a.log"));
        assert!(!ig.is_ignored("keep.log"));
    }
}
