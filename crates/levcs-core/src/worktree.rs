//! Writing into a working tree without following links.
//!
//! Checkout used to write by pathname: `create_dir_all`, then `fs::write`.
//! That failed in three ways:
//! - a directory on the way that had become a symlink sent the write
//!   outside the repository;
//! - a file that was a symlink was written through to its target;
//! - a file hard-linked elsewhere was overwritten in place.
//!
//! Here, every write walks its path one component at a time from a directory
//! descriptor, opening each with `O_NOFOLLOW`. It refuses any component that
//! is a symlink or not a directory, and it replaces the final file by renaming
//! a new one over it, so an old symbolic or hard link is replaced, never
//! written through. Checking a path and then opening it by name would leave
//! a window in which a directory could be swapped for a symlink; opening
//! relative to descriptors held open does not.

use std::path::Path;

use crate::error::{Error, Result};

/// The components of a repository-relative path, checked.
/// - No component may be empty, `.` or `..`, or contain NUL.
/// - No component may name `.levcs` as any file system would read it (see
///   [`names_metadata`]). At the root that would write into repository
///   metadata; deeper, it would make a directory that `levcs` takes for a
///   repository. A tree's own top-level `.levcs` entry is synthetic history
///   and is skipped before paths get here.
pub fn components(rel: &str) -> Result<Vec<&str>> {
    let parts: Vec<&str> = rel.split('/').collect();
    for p in &parts {
        if p.is_empty() || *p == "." || *p == ".." || p.contains('\0') {
            return Err(Error::InvalidPath(format!("{p:?} in {rel:?}")));
        }
        if names_metadata(p) {
            return Err(Error::InvalidPath(format!(
                "{p:?} in {rel:?} would write into repository metadata or \
                 create a nested repository"
            )));
        }
    }
    Ok(parts)
}

/// Whether a file system could take this name for `.levcs`: in any letter
/// case, as a case-insensitive one would (with Unicode folding, so `ſ` is
/// an `s`), and without the code points HFS+ drops from names, which is how
/// Git guards `.git` on macOS.
fn names_metadata(name: &str) -> bool {
    let hfs_ignored = |c: &char| {
        matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}')
            || *c == '\u{feff}'
    };
    name.chars()
        .filter(|c| !hfs_ignored(c))
        .flat_map(char::to_uppercase)
        .eq(".LEVCS".chars())
}

/// The permissions a written file gets.
///
/// Files used to be written in place, which kept the permissions of the file
/// being written. Replacing a file creates a new one, so they are carried
/// over explicitly: a replaced regular file keeps its permission bits, and
/// a file set private stays private across a checkout. Set-user-ID,
/// set-group-ID and sticky bits are never carried or set, as an in-place
/// write would have cleared them. A new file, or one replacing a symlink,
/// gets the default unless the permissions are given exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perms {
    /// Not executable, as a tree records it: execute bits cleared.
    Regular,
    /// Executable, as a tree records it: execute bits set wherever the
    /// file is readable.
    Executable,
    /// Unchanged. For writes that change contents only (a merge, a review).
    Keep,
    /// These permission bits, whatever was there: a cache restores the
    /// mode it saved.
    Exact(u32),
}

#[cfg_attr(not(unix), allow(dead_code))]
fn refuse(rel: &str, why: &str) -> Error {
    Error::Other(format!("refusing to write {rel:?}: {why}"))
}

#[cfg(unix)]
mod imp {
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{
        fchmod, fstat, mkdirat, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
        OFlags, CWD,
    };
    use rustix::io::Errno;

    use super::{components, refuse, Perms};
    use crate::error::{Error, Result};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn io(path: &Path, e: Errno) -> Error {
        Error::Io {
            path: Some(path.to_path_buf()),
            source: e.into(),
        }
    }

    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    /// The permission bits for a file written with `perms` over a regular
    /// file whose mode was `old`, or over nothing (`None`). `None` back
    /// leaves a new file its default, the umask applied.
    fn replaced_mode(perms: Perms, old: Option<u32>) -> Option<u32> {
        match (perms, old.map(|m| m & 0o777)) {
            (Perms::Exact(m), _) => Some(m & 0o777),
            (_, None) => None,
            (Perms::Keep, Some(old)) => Some(old),
            (Perms::Regular, Some(old)) => Some(old & !0o111),
            (Perms::Executable, Some(old)) => Some(old | ((old & 0o444) >> 2)),
        }
    }

    /// The mode of the regular file `name` in `dir`, if that is what is
    /// there. A symlink's mode is meaningless, and its target's is not
    /// this file's to copy.
    fn regular_mode(dir: &OwnedFd, name: &str) -> Option<u32> {
        match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {
                Some(st.st_mode & 0o7777)
            }
            _ => None,
        }
    }

    /// A working tree, held open by its root directory.
    pub struct Worktree {
        root: OwnedFd,
        root_path: PathBuf,
    }

    impl Worktree {
        /// Open the working tree at `root`. The root itself may be reached
        /// through a symlink: it is the path the caller chose. Nothing below
        /// it is.
        pub fn open(root: &Path) -> Result<Self> {
            let fd = openat(
                CWD,
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| io(root, e))?;
            Ok(Self {
                root: fd,
                root_path: root.to_path_buf(),
            })
        }

        /// The directory holding `comps`, opened component by component
        /// without following symlinks. With `create`, missing directories
        /// are made; without it, a missing one yields `None`.
        fn dir(&self, rel: &str, comps: &[&str], create: bool) -> Result<Option<OwnedFd>> {
            let mut cur = openat(&self.root, ".", dir_flags(), Mode::empty())
                .map_err(|e| io(&self.root_path, e))?;
            for c in comps {
                cur = match openat(&cur, *c, dir_flags(), Mode::empty()) {
                    Ok(fd) => fd,
                    Err(Errno::NOENT) if create => {
                        match mkdirat(&cur, *c, Mode::RWXU | Mode::RWXG | Mode::RWXO) {
                            Ok(()) | Err(Errno::EXIST) => {}
                            Err(e) => return Err(io(&self.root_path.join(rel), e)),
                        }
                        openat(&cur, *c, dir_flags(), Mode::empty()).map_err(|e| match e {
                            Errno::LOOP | Errno::NOTDIR => {
                                refuse(rel, &format!("{c:?} is a symlink or not a directory"))
                            }
                            e => io(&self.root_path.join(rel), e),
                        })?
                    }
                    Err(Errno::NOENT) => return Ok(None),
                    Err(Errno::LOOP) | Err(Errno::NOTDIR) => {
                        return Err(refuse(
                            rel,
                            &format!("{c:?} is a symlink or not a directory"),
                        ))
                    }
                    Err(e) => return Err(io(&self.root_path.join(rel), e)),
                };
            }
            Ok(Some(cur))
        }

        /// Check, before anything is written, that each path's existing
        /// directories are real directories, and that none of the paths
        /// names an existing directory. A path can still be refused when
        /// written, if the tree changes in between, but a checkout will
        /// not stop part way for a reason that was visible at the start.
        pub fn preflight<'a>(&self, rels: impl IntoIterator<Item = &'a str>) -> Result<()> {
            for rel in rels {
                let comps = components(rel)?;
                let (name, parents) = comps.split_last().expect("split yields a component");
                let Some(dir) = self.dir(rel, parents, false)? else {
                    continue;
                };
                match statat(&dir, *name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Directory => {
                        return Err(refuse(rel, "a directory is in the way"))
                    }
                    Ok(_) | Err(Errno::NOENT) => {}
                    Err(e) => return Err(io(&self.root_path.join(rel), e)),
                }
            }
            Ok(())
        }

        /// Replace the file at `rel` with `bytes`. A new file is written
        /// beside it and renamed over it, so whatever `rel` was (a symlink,
        /// a hard link to a file elsewhere) is replaced, not written through.
        /// The new file is the caller's, whoever owned the old one.
        pub fn write_file(&self, rel: &str, bytes: &[u8], perms: Perms) -> Result<()> {
            let comps = components(rel)?;
            let (name, parents) = comps.split_last().expect("split yields a component");
            let dir = self.dir(rel, parents, true)?.expect("created");
            let mut mode =
                Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH;
            if perms == Perms::Executable {
                mode |= Mode::XUSR | Mode::XGRP | Mode::XOTH;
            }
            let keep = replaced_mode(perms, regular_mode(&dir, name)).map(Mode::from_raw_mode);
            let tmp = format!(
                ".levcs-write.{}.{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let fd = openat(
                &dir,
                tmp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode,
            )
            .map_err(|e| io(&self.root_path.join(rel), e))?;
            let written = match keep {
                Some(m) => fchmod(&fd, m).map_err(std::io::Error::from),
                None => Ok(()),
            }
            .and_then(|()| std::fs::File::from(fd).write_all(bytes));
            if let Err(e) = written {
                let _ = unlinkat(&dir, tmp.as_str(), AtFlags::empty());
                return Err(Error::Io {
                    path: Some(self.root_path.join(rel)),
                    source: e,
                });
            }
            if let Err(e) = renameat(&dir, tmp.as_str(), &dir, *name) {
                let _ = unlinkat(&dir, tmp.as_str(), AtFlags::empty());
                return Err(match e {
                    Errno::ISDIR | Errno::NOTEMPTY | Errno::EXIST => {
                        refuse(rel, "a directory is in the way")
                    }
                    e => io(&self.root_path.join(rel), e),
                });
            }
            Ok(())
        }

        /// Whether `rel` is already a regular file holding `bytes`, with the
        /// permissions writing them with `perms` would leave, so that the
        /// write can be skipped. Nothing on the way is followed, and only a
        /// regular file is opened; anything else there is `false`.
        pub fn holds(&self, rel: &str, bytes: &[u8], perms: Perms) -> Result<bool> {
            let comps = components(rel)?;
            let (name, parents) = comps.split_last().expect("split yields a component");
            let Some(dir) = self.dir(rel, parents, false)? else {
                return Ok(false);
            };
            if regular_mode(&dir, name).is_none() {
                return Ok(false);
            }
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let fd = match openat(&dir, *name, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) | Err(Errno::LOOP) | Err(Errno::ACCESS) => return Ok(false),
                Err(e) => return Err(io(&self.root_path.join(rel), e)),
            };
            // Checked again on what was opened, in case it changed.
            let st = fstat(&fd).map_err(|e| io(&self.root_path.join(rel), e))?;
            let mode = st.st_mode & 0o7777;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                || replaced_mode(perms, Some(mode)) != Some(mode)
                || u64::try_from(st.st_size).ok() != Some(bytes.len() as u64)
            {
                return Ok(false);
            }
            let mut cur = Vec::with_capacity(bytes.len());
            std::fs::File::from(fd)
                .read_to_end(&mut cur)
                .map_err(|e| Error::Io {
                    path: Some(self.root_path.join(rel)),
                    source: e,
                })?;
            Ok(cur == bytes)
        }

        /// Remove the file at `rel`. A symlink there is removed itself, not
        /// its target; a directory there is refused. `false` if nothing was
        /// there.
        pub fn remove_file(&self, rel: &str) -> Result<bool> {
            let comps = components(rel)?;
            let (name, parents) = comps.split_last().expect("split yields a component");
            let Some(dir) = self.dir(rel, parents, false)? else {
                return Ok(false);
            };
            match unlinkat(&dir, *name, AtFlags::empty()) {
                Ok(()) => Ok(true),
                Err(Errno::NOENT) => Ok(false),
                Err(Errno::ISDIR) | Err(Errno::PERM) => {
                    Err(refuse(rel, "it is a directory, not a file"))
                }
                Err(e) => Err(io(&self.root_path.join(rel), e)),
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    //! Fails closed. Writing safely rests on opening each directory relative
    //! to the last without following links, which is not available here. A
    //! version that checked each path and then used it was not only racy:
    //! it followed a symlink left at its temporary name, and Windows reads
    //! `\` as a separator, so a name ordinary on Unix (`..\outside`,
    //! `.levcs\config`) escaped deterministically. Until there is an
    //! equivalent, no working tree is written on these platforms.
    use std::convert::Infallible;
    use std::path::Path;

    use super::Perms;
    use crate::error::{Error, Result};

    /// Never constructed: [`Worktree::open`] always refuses.
    pub struct Worktree {
        never: Infallible,
    }

    impl Worktree {
        pub fn open(root: &Path) -> Result<Self> {
            Err(Error::Other(format!(
                "refusing to write the working tree at {root:?}: levcs writes \
                 working trees only on Unix, where it can do so without \
                 following links"
            )))
        }

        pub fn preflight<'a>(&self, _rels: impl IntoIterator<Item = &'a str>) -> Result<()> {
            match self.never {}
        }

        pub fn write_file(&self, _rel: &str, _bytes: &[u8], _perms: Perms) -> Result<()> {
            match self.never {}
        }

        pub fn holds(&self, _rel: &str, _bytes: &[u8], _perms: Perms) -> Result<bool> {
            match self.never {}
        }

        pub fn remove_file(&self, _rel: &str) -> Result<bool> {
            match self.never {}
        }
    }
}

pub use imp::Worktree;

/// Open `root` as a working tree. See [`Worktree`].
pub fn open(root: &Path) -> Result<Worktree> {
    Worktree::open(root)
}
