//! `levcs-gate`: the deployment gate.
//!
//! An instance is relied on only after this passes on the host it will run
//! on, with the binaries it will run. The gate starts the `levcs-instance`
//! it is given on a throwaway root and port, from a config file as the
//! service reads one, and drives it with the `levcs` it is given and with
//! requests of its own:
//!
//! - a bad config is refused at startup;
//! - two pushes and a clone, then work pushed from the clone and pulled
//!   back;
//! - refusals: paths that would leave the root, creation by a key not
//!   named in `creators`, reads of a private repository, a stale
//!   compare-and-swap, a malformed history, an incomplete history, and a
//!   pack that decodes past the instance's limit;
//! - recovery: after the process is killed, and of a push of two refs cut
//!   off between its ref writes, by the instance's own writer, with its
//!   journal on disk;
//! - a graceful stop, and backups made and restored by the scripts
//!   `deploy/README.md` uses, built into the gate as they are in `deploy/`:
//!   a backup restored, and a damaged one refused with nothing changed.
//!
//! It stops at its first failure, since later checks build on earlier
//! ones, and keeps its directory to look at. It exits 0 only when every
//! check passes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};

use levcs_client::{Client, ClientError};
use levcs_core::refs::Head;
use levcs_core::{
    Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Refs, Repository, Tree, TreeEntry,
    ZERO_ID,
};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::keychain::Keychain;
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit};
use levcs_protocol::{Pack, PushManifest, PushUpdate};

/// What the gate's instance decodes of one push, at most: small, so that
/// the oversized pack is cheap to send.
const MAX_PACK_BYTES: u64 = 16 << 20;

/// How long any one command or request may take.
const DEADLINE: Duration = Duration::from_secs(120);

/// In the instance's environment, it ends itself right after a push's
/// n-th ref write, with [`EXITED_AFTER_REF_WRITES`]: how a push of the
/// binary checked is cut off between its ref writes. As `levcs-instance`
/// reads it.
const EXIT_AFTER_REF_WRITES: &str = "LEVCS_INSTANCE_EXIT_AFTER_REF_WRITES";
const EXITED_AFTER_REF_WRITES: i32 = 86;

/// The guide whose procedures the gate runs.
const GUIDE: &str = include_str!("../../../deploy/README.md");

/// The scripts `deploy/README.md` backs up and restores with.
const BACKUP_SCRIPT: &str = include_str!("../../../deploy/levcs-backup");
const RESTORE_SCRIPT: &str = include_str!("../../../deploy/levcs-restore");

const USAGE: &str = "\
usage: levcs-gate [--levcs PATH] [--instance PATH] [--dir DIR] [--keep]

  --levcs PATH      the levcs CLI to drive (default: beside this binary, else on PATH)
  --instance PATH   the levcs-instance to check (default: beside this binary, else on PATH)
  --dir DIR         where to make the gate's directory (default: the temp directory)
  --keep            keep the gate's directory when every check passes
";

fn main() {
    let gate = match Gate::from_args() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("levcs-gate: {e:#}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    std::process::exit(gate.run());
}

/// One step of the gate.
type Check = fn(&mut Gate) -> Result<()>;

const CHECKS: &[(&str, Check)] = &[
    ("a bad config is refused at startup", Gate::bad_config),
    ("the instance starts and says what it takes", Gate::starts),
    ("two pushes and a clone", Gate::two_pushes_and_a_clone),
    (
        "paths that would leave the root reach nothing",
        Gate::traversal,
    ),
    (
        "a key not named in creators creates nothing",
        Gate::unauthorized_creation,
    ),
    (
        "a private repository is read by members only",
        Gate::private_reads,
    ),
    (
        "a stale compare-and-swap is refused",
        Gate::stale_compare_and_swap,
    ),
    ("a malformed history is refused", Gate::malformed_history),
    ("an incomplete history is refused", Gate::incomplete_history),
    (
        "a pack past the decoded limit is refused",
        Gate::oversized_pack,
    ),
    ("the instance recovers from being killed", Gate::killed),
    (
        "a push cut off between its ref writes is rolled back",
        Gate::interrupted_push,
    ),
    (
        "backups restore, and a damaged one changes nothing",
        Gate::backup_and_restore,
    ),
    ("the instance stops gracefully", Gate::graceful_stop),
    (
        "the guide's procedures stop at a failure",
        Gate::guide_procedures,
    ),
];

struct Gate {
    levcs: PathBuf,
    instance: PathBuf,
    keep: bool,
    /// The gate's directory: workspaces, keychain, instance root.
    dir: PathBuf,
    xdg: PathBuf,
    root: PathBuf,
    config: PathBuf,
    log: PathBuf,
    port: u16,
    base: String,
    server: Option<Child>,
    /// The repository the checks share, once pushed.
    repo_id: String,
}

/// A command's outcome: its status and what it wrote, stdout then stderr.
struct Ran {
    status: ExitStatus,
    out: String,
}

impl Gate {
    fn from_args() -> Result<Gate> {
        let mut levcs = None;
        let mut instance = None;
        let mut parent = std::env::temp_dir();
        let mut keep = false;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let mut value = || args.next().ok_or_else(|| anyhow!("{arg} needs a value"));
            match arg.as_str() {
                "--levcs" => levcs = Some(PathBuf::from(value()?)),
                "--instance" => instance = Some(PathBuf::from(value()?)),
                "--dir" => parent = PathBuf::from(value()?),
                "--keep" => keep = true,
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                other => bail!("unknown argument {other:?}"),
            }
        }
        // Absolute, since the commands run from directories of their own.
        let levcs = std::fs::canonicalize(binary(levcs, "levcs")?)?;
        let instance = std::fs::canonicalize(binary(instance, "levcs-instance")?)?;
        let dir = parent.join(format!(
            "levcs-gate-{}-{}",
            std::process::id(),
            now_micros()
        ));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let dir = std::fs::canonicalize(&dir)?;
        let port = free_port()?;
        Ok(Gate {
            levcs,
            instance,
            keep,
            xdg: dir.join("xdg"),
            root: dir.join("root"),
            config: dir.join("instance.toml"),
            log: dir.join("instance.log"),
            dir,
            port,
            base: format!("http://127.0.0.1:{port}/levcs/v1"),
            server: None,
            repo_id: String::new(),
        })
    }

    fn run(mut self) -> i32 {
        println!(
            "levcs-gate: {} with {}, in {}",
            self.instance.display(),
            self.levcs.display(),
            self.dir.display()
        );
        for (name, check) in CHECKS {
            let started = Instant::now();
            match check(&mut self) {
                Ok(()) => println!("ok    {name} ({:.1}s)", started.elapsed().as_secs_f64()),
                Err(e) => {
                    println!("FAIL  {name}\n      {e:#}");
                    if let Some(mut server) = self.server.take() {
                        let _ = server.kill();
                        let _ = server.wait();
                    }
                    println!(
                        "levcs-gate: failed; its directory is kept: {}\n\
                         the instance's log: {}",
                        self.dir.display(),
                        self.log.display()
                    );
                    return 1;
                }
            }
        }
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
        println!("levcs-gate: every check passed");
        0
    }

    // ---- the checks ----

    fn bad_config(&mut self) -> Result<()> {
        let config = self.dir.join("bad.toml");
        std::fs::write(
            &config,
            format!(
                "root = {:?}\nbind = \"127.0.0.1:{}\"\ncreators = [\"not-a-key\"]\n\n\
                 [[mirrors]]\nrepo_id = \"{}\"\nsource = \"http://127.0.0.1:9/levcs/v1\"\n",
                self.dir.join("bad-root"),
                self.port,
                "ab".repeat(32)
            ),
        )?;
        let ran = run(Command::new(&self.instance).arg("--config").arg(&config))?;
        ensure!(!ran.status.success(), "it started: {}", ran.out);
        for refusal in ["invalid configuration", "not-a-key", "mirroring is refused"] {
            ensure!(ran.out.contains(refusal), "no {refusal:?} in: {}", ran.out);
        }
        Ok(())
    }

    fn starts(&mut self) -> Result<()> {
        self.levcs(&self.dir, &["key", "generate", "owner"])?;
        self.levcs(&self.dir, &["key", "generate", "stranger"])?;
        let owner = self.levcs(&self.dir, &["key", "show", "owner"])?;
        std::fs::write(
            &self.config,
            format!(
                "root = {:?}\nbind = \"127.0.0.1:{}\"\ncreators = [{:?}]\n\n\
                 [limits]\nmax_pack_bytes = {MAX_PACK_BYTES}\n",
                self.root,
                self.port,
                owner.trim()
            ),
        )?;
        self.start()?;
        let info = Client::new(&self.base).instance_info()?;
        let limits = info
            .limits
            .ok_or_else(|| anyhow!("the instance does not say what it takes"))?;
        ensure!(
            limits.max_pack_bytes == MAX_PACK_BYTES,
            "it takes {} decoded bytes, not the configured {MAX_PACK_BYTES}",
            limits.max_pack_bytes
        );
        Ok(())
    }

    fn two_pushes_and_a_clone(&mut self) -> Result<()> {
        let a = self.dir.join("a");
        std::fs::create_dir_all(a.join("src"))?;
        self.levcs(&a, &["init", "--key", "owner"])?;
        std::fs::write(a.join("README"), "the gate's repository\n")?;
        std::fs::write(a.join("src/lib.rs"), "pub fn one() {}\n")?;
        self.levcs(&a, &["track", "--all"])?;
        self.levcs(&a, &["commit", "-m", "one", "--key", "owner"])?;
        self.levcs(&a, &["instance", "--set", &self.base])?;
        let dry = self.levcs(&a, &["push", "--dry-run", "--key", "owner"])?;
        ensure!(dry.contains("within the instance's limits"), "{dry}");
        self.levcs(&a, &["push", "--key", "owner"])?;
        self.repo_id = self.only_repo()?;
        std::fs::write(a.join("src/lib.rs"), "pub fn one() {}\npub fn two() {}\n")?;
        self.levcs(&a, &["commit", "-m", "two", "--key", "owner"])?;
        self.levcs(&a, &["push", "--key", "owner"])?;
        ensure!(self.main()? == read_ref(&a, "refs/branches/main")?);

        self.levcs(
            &self.dir,
            &["clone", &self.repo_id, "b", "--from", &self.base],
        )?;
        let b = self.dir.join("b");
        for file in ["README", "src/lib.rs"] {
            ensure!(
                std::fs::read(a.join(file))? == std::fs::read(b.join(file))?,
                "the clone's {file} differs"
            );
        }
        for r in [
            "refs/branches/main",
            "refs/authority/genesis",
            "refs/authority/current",
        ] {
            ensure!(
                read_ref(&a, r)? == read_ref(&b, r)?,
                "the clone's {r} differs"
            );
        }
        self.levcs(&b, &["verify"])?;

        std::fs::write(b.join("NOTES"), "from the clone\n")?;
        self.levcs(&b, &["track", "NOTES"])?;
        self.levcs(&b, &["commit", "-m", "three", "--key", "owner"])?;
        self.levcs(&b, &["push", "--key", "owner"])?;
        ensure!(self.main()? == read_ref(&b, "refs/branches/main")?);
        self.levcs(&a, &["pull"])?;
        ensure!(
            read_ref(&a, "refs/remote/origin/branches/main")? == self.main()?,
            "the pull did not record the instance's main"
        );
        self.levcs(&a, &["verify"])?;
        Ok(())
    }

    fn traversal(&mut self) -> Result<()> {
        // A repository beside the root: what a path that escaped the root
        // would reach. The audit read one this way (C3).
        let beside = self.dir.join("beside");
        command_ok(
            Command::new("cp")
                .arg("-a")
                .arg(self.root.join(&self.repo_id))
                .arg(&beside),
        )?;
        let before = entries(&self.dir)?;
        for id in [
            "..%2Fbeside",
            "%2e%2e%2fbeside",
            "..%252Fbeside",
            "..%2F..%2F..%2Fetc",
        ] {
            for route in ["info", "refs", "pack?want="] {
                let (status, body) = self.get(&format!("/levcs/v1/repos/{id}/{route}"))?;
                ensure!(status == 404, "{id}/{route} answered {status}: {body}");
            }
        }
        // Nor does an init through one, signed by a creator over the path
        // as the instance decodes it, as an attacker would sign it.
        let a = Repository::discover(self.dir.join("a"))?;
        let genesis = a
            .genesis_authority()?
            .ok_or_else(|| anyhow!("a has no genesis"))?;
        let genesis = a.objects.read_raw(genesis)?;
        for (sent, decoded) in [
            ("..%2Fescaped", "../escaped"),
            ("%2e%2e%2fescaped", "../escaped"),
        ] {
            let (status, body) = self.signed_post(
                &format!("/levcs/v1/repos/{sent}/init"),
                &format!("/repos/{decoded}/init"),
                &genesis,
            )?;
            ensure!(status == 404, "an init at {sent} answered {status}: {body}");
        }
        ensure!(
            entries(&self.dir)? == before,
            "something was made beside the root"
        );
        std::fs::remove_dir_all(&beside)?;
        Ok(())
    }

    fn unauthorized_creation(&mut self) -> Result<()> {
        let c = self.dir.join("c");
        std::fs::create_dir_all(&c)?;
        self.levcs(&c, &["init", "--key", "stranger"])?;
        std::fs::write(c.join("README"), "not wanted here\n")?;
        self.levcs(&c, &["track", "README"])?;
        self.levcs(&c, &["commit", "-m", "one", "--key", "stranger"])?;
        self.levcs(&c, &["instance", "--set", &self.base])?;
        let ran = self.levcs_ran(&c, &["push", "--key", "stranger"])?;
        ensure!(!ran.status.success(), "the push succeeded: {}", ran.out);
        ensure!(
            ran.out.contains("may not create repositories"),
            "{}",
            ran.out
        );
        ensure!(self.repos()?.len() == 1, "a repository was created");
        Ok(())
    }

    fn private_reads(&mut self) -> Result<()> {
        let owner = self.secret("owner")?;
        let p = self.dir.join("private");
        let repo = Repository::init_skeleton(&p)?;
        let mut body = AuthorityBody {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            repo_id: ZERO_ID,
            previous_authority: ZERO_ID,
            version: 1,
            created_micros: now_micros(),
            members: vec![MemberEntry {
                key: owner.public(),
                handle: "owner".into(),
                role: Role::Owner,
                added_micros: now_micros(),
                added_by: owner.public(),
            }],
            policy: vec![PolicyEntry {
                key: "public_read".into(),
                value: vec![0],
            }],
        };
        body.normalize()?;
        body.assign_genesis_repo_id()?;
        let id = body.repo_id.to_hex();
        let genesis = repo.write_signed(&sign_authority(&body, &owner)?)?;
        repo.set_genesis_authority(genesis)?;
        repo.set_current_authority(genesis)?;
        let (tip, objects) = commit(&owner, genesis, None, &[("secret.txt", b"kept\n")])?;
        for bytes in &objects {
            repo.objects.write_raw(bytes)?;
        }
        repo.refs.write("refs/branches/main", tip)?;
        repo.refs
            .write_head(&Head::Branch("refs/branches/main".into()))?;
        self.levcs(&p, &["instance", "--set", &self.base])?;
        self.levcs(&p, &["push", "--key", "owner"])?;

        let ran = self.levcs_ran(&self.dir, &["clone", &id, "anyone", "--from", &self.base])?;
        ensure!(!ran.status.success(), "an anonymous clone succeeded");
        ensure!(!self.dir.join("anyone").exists());
        let (status, _) = self.get(&format!("/levcs/v1/repos/{id}/info"))?;
        ensure!(status == 404, "an anonymous read answered {status}");
        let stranger = Client::new(&self.base).with_reader(Arc::new(self.secret("stranger")?));
        match stranger.repo_info(&id) {
            Err(ClientError::Server { status: 404, .. }) => {}
            other => bail!("a stranger's signed read was answered {other:?}"),
        }
        self.levcs(
            &self.dir,
            &[
                "clone", &id, "member", "--from", &self.base, "--key", "owner",
            ],
        )?;
        ensure!(std::fs::read(self.dir.join("member/secret.txt"))? == b"kept\n");
        Ok(())
    }

    fn stale_compare_and_swap(&mut self) -> Result<()> {
        let main = self.main()?;
        let first = self.first_commit()?;
        let (tip, objects) = commit(
            &self.secret("owner")?,
            self.current()?,
            Some(main),
            &[("stale.txt", b"stale\n")],
        )?;
        let refused = self.push(Some(first), tip, &objects)?;
        ensure!(refused.0 == 409, "answered {}: {}", refused.0, refused.1);
        ensure!(self.main()? == main, "main moved");
        Ok(())
    }

    fn malformed_history(&mut self) -> Result<()> {
        let main = self.main()?;
        let (_, mut objects) = commit(
            &self.secret("owner")?,
            self.current()?,
            Some(main),
            &[("forged.txt", b"forged\n")],
        )?;
        // The commit, last, with its signature zeroed.
        let commit = objects.last_mut().unwrap();
        let mut signed = levcs_core::SignedObject::parse(commit)?;
        signed.signatures[0].signature = [0; 64];
        *commit = signed.serialize();
        let tip = levcs_core::blake3_hash(commit);
        let refused = self.push(Some(main), tip, &objects)?;
        ensure!(refused.0 == 403, "answered {}: {}", refused.0, refused.1);
        ensure!(self.main()? == main, "main moved");
        Ok(())
    }

    fn incomplete_history(&mut self) -> Result<()> {
        let main = self.main()?;
        let (tip, objects) = commit(
            &self.secret("owner")?,
            self.current()?,
            Some(main),
            &[("missing.txt", b"never sent\n")],
        )?;
        // Everything but the blob.
        let refused = self.push(Some(main), tip, &objects[1..])?;
        ensure!(
            (400..500).contains(&refused.0),
            "answered {}: {}",
            refused.0,
            refused.1
        );
        ensure!(self.main()? == main, "main moved");
        let (status, _) = self.get(&format!("/levcs/v1/repos/{}/objects/{tip}", self.repo_id))?;
        ensure!(status == 404, "the refused commit is served ({status})");
        Ok(())
    }

    fn oversized_pack(&mut self) -> Result<()> {
        let main = self.main()?;
        // Twice the limit, decoded; a few kilobytes as sent.
        let zeros = vec![0u8; 2 * MAX_PACK_BYTES as usize];
        let big = self.dir.join("big");
        self.levcs(
            &self.dir,
            &["clone", &self.repo_id, "big", "--from", &self.base],
        )?;
        std::fs::write(big.join("zeros.bin"), &zeros)?;
        self.levcs(&big, &["track", "zeros.bin"])?;
        self.levcs(&big, &["commit", "-m", "zeros", "--key", "owner"])?;
        let dry = self.levcs(&big, &["push", "--dry-run", "--key", "owner"])?;
        ensure!(dry.contains("the instance would refuse it"), "{dry}");
        let ran = self.levcs_ran(&big, &["push", "--key", "owner"])?;
        ensure!(
            !ran.status.success() && ran.out.contains("nothing was sent"),
            "{}",
            ran.out
        );

        // Sent anyway, as a client that does not check would.
        let (tip, objects) = commit(
            &self.secret("owner")?,
            self.current()?,
            Some(main),
            &[("zeros.bin", &zeros)],
        )?;
        let refused = self.push(Some(main), tip, &objects)?;
        ensure!(refused.0 == 413, "answered {}: {}", refused.0, refused.1);
        ensure!(self.main()? == main, "main moved");
        Ok(())
    }

    fn killed(&mut self) -> Result<()> {
        let main = self.main()?;
        let mut server = self.server.take().ok_or_else(|| anyhow!("not running"))?;
        server.kill()?;
        server.wait()?;
        self.start()?;
        ensure!(self.main()? == main, "main changed across the restart");
        self.clone_and_verify("after-kill")
    }

    fn interrupted_push(&mut self) -> Result<()> {
        let main = self.main()?;
        let side = "refs/branches/gate-interrupted";
        let (tip, objects) = commit(
            &self.secret("owner")?,
            self.current()?,
            Some(main),
            &[("interrupted.txt", b"never published\n")],
        )?;
        // The instance, told to end itself right after a push's first ref
        // write, and a push of two refs.
        self.stop()?;
        self.start_with(&[(EXIT_AFTER_REF_WRITES, "1")])?;
        let sent = self.send(
            &[("refs/branches/main", Some(main), tip), (side, None, tip)],
            &objects,
        )?;
        ensure!(sent.is_err(), "the push was answered: it was not cut off");
        let status = self.exited()?;
        ensure!(
            status.code() == Some(EXITED_AFTER_REF_WRITES),
            "the instance ended with {status}, not after a ref write"
        );
        // Cut off between its ref writes: its journal on disk, and one ref
        // of the two moved.
        let levcs = self.root.join(&self.repo_id).join(".levcs");
        ensure!(
            levcs.join("ref-transaction/record").is_file(),
            "the push left no journal of its ref writes"
        );
        let refs = Refs::new(levcs);
        let moved = [
            refs.read("refs/branches/main")? == Some(tip),
            refs.read(side)? == Some(tip),
        ];
        ensure!(
            moved.iter().filter(|m| **m).count() == 1,
            "not one ref of the two moved before the cut: {moved:?}"
        );

        self.start()?;
        let log = std::fs::read_to_string(&self.log)?;
        ensure!(
            log.contains(&format!(
                "{}: rolled back an interrupted push",
                self.repo_id
            )),
            "the start did not say it rolled the push back"
        );
        ensure!(self.main()? == main, "main was not put back");
        let info = Client::new(&self.base).repo_info(&self.repo_id)?;
        ensure!(
            !info.branches.contains_key("gate-interrupted"),
            "the second ref was not put back"
        );
        self.clone_and_verify("after-interrupted")
    }

    fn backup_and_restore(&mut self) -> Result<()> {
        let backups = self.dir.join("backups");
        std::fs::create_dir_all(&backups)?;
        let backup = backups.join("levcs.tgz");
        let backed_up = self.main()?;
        let aside = self.dir.join("root.before-restore");

        // deploy/README.md, "Backups".
        self.stop()?;
        self.script("levcs-backup", &[&backup, &self.root])?;
        // It never overwrites an archive: one that exists, or one that
        // appears while it runs (here, as it reads its own back).
        let made = std::fs::read(&backup)?;
        let ran = self.script_ran("levcs-backup", &[&backup, &self.root], &[])?;
        ensure!(!ran.status.success(), "a backup overwrote an archive");
        let racing = backups.join("racing.tgz");
        let shims = backups.join("shims");
        std::fs::create_dir_all(&shims)?;
        std::fs::write(
            shims.join("tar"),
            "#!/bin/sh\n\"$GATE_TAR\" \"$@\" || exit $?\n\
             case \"$1\" in -tzf) cp \"$GATE_PLANT\" \"$GATE_DEST\" ;; esac\n",
        )?;
        command_ok(Command::new("chmod").arg("0755").arg(shims.join("tar")))?;
        let path = format!(
            "{}:{}",
            shims.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let tar = on_path("tar").ok_or_else(|| anyhow!("no tar on PATH"))?;
        let ran = self.script_ran(
            "levcs-backup",
            &[&racing, &self.root],
            &[
                ("PATH", path.as_ref()),
                ("GATE_TAR", tar.as_os_str()),
                ("GATE_PLANT", backup.as_os_str()),
                ("GATE_DEST", racing.as_os_str()),
            ],
        )?;
        ensure!(
            !ran.status.success() && std::fs::read(&racing)? == made,
            "a backup overwrote an archive that appeared while it ran: {}",
            ran.out
        );
        ensure!(std::fs::read(&backup)? == made, "the first archive changed");
        self.start()?;

        // Work after the backup, from the clone, which the instance's main
        // is.
        let b = self.dir.join("b");
        ensure!(read_ref(&b, "refs/branches/main")? == backed_up);
        std::fs::write(b.join("AFTER"), "after the backup\n")?;
        self.levcs(&b, &["track", "AFTER"])?;
        self.levcs(&b, &["commit", "-m", "after the backup", "--key", "owner"])?;
        self.levcs(&b, &["push", "--key", "owner"])?;
        let after = self.main()?;
        ensure!(after != backed_up);

        // A backup missing an object its refs reach is refused, and nothing
        // is changed: the service is not started on it.
        let name = self
            .root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        // So is one holding anything that is not a repository the
        // instance would serve: a repository without its metadata, an
        // entry not named by an id, a repository under another's id.
        let id = self.repo_id.clone();
        let other = "0".repeat(64);
        let refusals: Vec<(PathBuf, &str)> = vec![
            (self.damaged(&backup, &backups, &name)?, "does not verify"),
            (
                self.variant(&backup, &backups, &name, "no-metadata", |root| {
                    Ok(std::fs::remove_dir_all(root.join(&id).join(".levcs"))?)
                })?,
                "no repository metadata",
            ),
            (
                self.variant(&backup, &backups, &name, "stray", |root| {
                    Ok(std::fs::write(root.join(".stray"), "not a repository\n")?)
                })?,
                ".stray: not named by a repository id",
            ),
            (
                self.variant(&backup, &backups, &name, "misnamed", |root| {
                    Ok(std::fs::rename(root.join(&id), root.join(&other))?)
                })?,
                "holds a repository other than the one it is named for",
            ),
        ];
        self.stop()?;
        for (archive, why) in &refusals {
            let ran = self.script_ran("levcs-restore", &[archive, &self.root], &[])?;
            ensure!(
                !ran.status.success(),
                "{} was restored: {}",
                archive.display(),
                ran.out
            );
            ensure!(
                ran.out.contains(why) && ran.out.contains("nothing was changed"),
                "{}: no {why:?} in: {}",
                archive.display(),
                ran.out
            );
            ensure!(
                read_ref(&self.root.join(&self.repo_id), "refs/branches/main")? == after,
                "the refused restore changed the root"
            );
            ensure!(!aside.exists(), "the refused restore set the root aside");
        }

        // deploy/README.md, "Restoring".
        self.script("levcs-restore", &[&backup, &self.root])?;
        ensure!(aside.is_dir(), "the replaced root was not kept");
        self.start()?;
        ensure!(
            self.main()? == backed_up,
            "the restore does not hold the backup's main"
        );
        self.clone_and_verify("after-restore")?;
        // The workspace is ahead of the restored instance: its push lands.
        self.levcs(&b, &["push", "--key", "owner"])?;
        ensure!(self.main()? == after, "the workspace's push did not land");
        Ok(())
    }

    /// `backup`, a root named `name`, with one object the shared
    /// repository's main reaches removed, beside it in `backups`.
    fn damaged(&self, backup: &Path, backups: &Path, name: &str) -> Result<PathBuf> {
        self.variant(backup, backups, name, "damaged", |root| {
            let repo = Repository::discover(root.join(&self.repo_id))?;
            let main = repo
                .refs
                .read("refs/branches/main")?
                .ok_or_else(|| anyhow!("the backup has no main"))?;
            let tree = Commit::from_signed(&repo.read_signed(main)?)?.tree;
            let (_, blob) = repo
                .lookup_path(tree, "README")?
                .ok_or_else(|| anyhow!("the backup's main has no README"))?;
            Ok(std::fs::remove_file(repo.objects.path_for(blob))?)
        })
    }

    /// `backup`, a root named `name`, extracted, changed by `edit`, and
    /// archived again as `label`.tgz in `backups`.
    fn variant(
        &self,
        backup: &Path,
        backups: &Path,
        name: &str,
        label: &str,
        edit: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<PathBuf> {
        let work = backups.join(label);
        std::fs::create_dir_all(&work)?;
        command_ok(
            Command::new("tar")
                .arg("-C")
                .arg(&work)
                .arg("-xzf")
                .arg(backup),
        )?;
        edit(&work.join(name))?;
        let archive = backups.join(format!("{label}.tgz"));
        command_ok(
            Command::new("tar")
                .arg("-C")
                .arg(&work)
                .arg("-czf")
                .arg(&archive)
                .arg(name),
        )?;
        Ok(archive)
    }

    /// `deploy/README.md`'s backup, restore and update commands, run as
    /// written, on a copy of the stopped root: `sudo` and `systemctl` are
    /// stand-ins that log, and the system's paths are the gate's. A damaged
    /// backup's restore must stop before the service is started; a failed
    /// gate, before anything is replaced.
    fn guide_procedures(&mut self) -> Result<()> {
        let case = self.dir.join("guide");
        let paths = [
            "var/lib",
            "var/backups",
            "usr/local/bin",
            "bin",
            "target/release",
        ];
        for p in paths {
            std::fs::create_dir_all(case.join(p))?;
        }
        let (lib, backups, bin) = (
            case.join("var/lib"),
            case.join("var/backups"),
            case.join("bin"),
        );
        command_ok(
            Command::new("cp")
                .arg("-a")
                .arg(&self.root)
                .arg(lib.join("levcs")),
        )?;
        for (name, text) in [
            ("levcs-backup", BACKUP_SCRIPT),
            ("levcs-restore", RESTORE_SCRIPT),
            (
                "sudo",
                "#!/bin/sh\nif [ \"$1\" = -u ]; then shift 2; fi\nexec \"$@\"\n",
            ),
            ("systemctl", "#!/bin/sh\necho \"$*\" >> \"$GUIDE_LOG\"\n"),
            (
                "levcs-gate",
                "#!/bin/sh\necho \"levcs-gate $*\" >> \"$GUIDE_LOG\"\nexit \"$GATE_EXIT\"\n",
            ),
        ] {
            std::fs::write(bin.join(name), text)?;
            command_ok(Command::new("chmod").arg("0755").arg(bin.join(name)))?;
        }
        std::os::unix::fs::symlink(&self.levcs, bin.join("levcs"))?;
        std::fs::write(case.join("usr/local/bin/levcs-instance"), "running\n")?;
        std::fs::write(case.join("target/release/levcs-instance"), "new\n")?;
        let log = case.join("guide.log");
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let run = |heading: &str, archive: &str, gate_exit: &str| -> Result<(Ran, Vec<String>)> {
            let text = guide_block(heading)?
                .replace("/var/lib", &lib.to_string_lossy())
                .replace("/var/backups", &backups.to_string_lossy())
                .replace(
                    "/usr/local/bin",
                    &case.join("usr/local/bin").to_string_lossy(),
                )
                .replace("levcs-<date>.tgz", archive);
            std::fs::write(&log, "")?;
            let ran = run(Command::new("sh")
                .arg("-c")
                .arg(text)
                .current_dir(&case)
                .env("PATH", &path)
                .env("GUIDE_LOG", &log)
                .env("GATE_EXIT", gate_exit))?;
            let calls = std::fs::read_to_string(&log)?
                .lines()
                .map(String::from)
                .collect();
            Ok((ran, calls))
        };
        let stop_start = ["stop levcs-instance", "start levcs-instance"];
        let main = || read_ref(&lib.join("levcs").join(&self.repo_id), "refs/branches/main");

        let (ran, calls) = run("Backups", "", "0")?;
        ensure!(ran.status.success(), "the backup failed: {}", ran.out);
        ensure!(calls == stop_start, "the backup ran {calls:?}");
        let archive = std::fs::read_dir(&backups)?
            .next()
            .ok_or_else(|| anyhow!("the backup made no archive"))??
            .path();
        let damaged = self.damaged(&archive, &backups, "levcs")?;
        let before = main()?;

        let (ran, calls) = run(
            "Restoring",
            &damaged.file_name().unwrap().to_string_lossy(),
            "0",
        )?;
        ensure!(
            !ran.status.success(),
            "a damaged backup's restore succeeded"
        );
        ensure!(
            calls == ["stop levcs-instance"],
            "a damaged backup's restore ran {calls:?}"
        );
        ensure!(
            main()? == before && !lib.join("levcs.before-restore").exists(),
            "a damaged backup's restore changed the root"
        );
        let (ran, calls) = run(
            "Restoring",
            &archive.file_name().unwrap().to_string_lossy(),
            "0",
        )?;
        ensure!(ran.status.success(), "the restore failed: {}", ran.out);
        ensure!(calls == stop_start, "the restore ran {calls:?}");

        let (ran, calls) = run("Updating the binary", "", "1")?;
        ensure!(
            !ran.status.success(),
            "the update went on past a failed gate"
        );
        ensure!(
            calls.len() == 1 && calls[0].starts_with("levcs-gate"),
            "a failed gate's update ran {calls:?}"
        );
        ensure!(
            !case.join("usr/local/bin/levcs-instance.previous").exists(),
            "a failed gate's update copied the binary"
        );
        let (ran, calls) = run("Updating the binary", "", "0")?;
        ensure!(ran.status.success(), "the update failed: {}", ran.out);
        ensure!(calls[1..] == stop_start, "the update ran {calls:?}");
        ensure!(
            std::fs::read(case.join("usr/local/bin/levcs-instance.previous"))? == b"running\n"
                && std::fs::read(case.join("usr/local/bin/levcs-instance"))? == b"new\n",
            "the update did not keep the running binary and install the new one"
        );
        Ok(())
    }

    fn graceful_stop(&mut self) -> Result<()> {
        self.stop()?;
        let log = std::fs::read_to_string(&self.log)?;
        ensure!(
            log.contains("stopping: no new requests"),
            "no stopping line in the log"
        );
        Ok(())
    }

    // ---- the instance ----

    fn start(&mut self) -> Result<()> {
        self.start_with(&[])
    }

    /// Start the instance with `env` added to its environment.
    fn start_with(&mut self, env: &[(&str, &str)]) -> Result<()> {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)?;
        let mut server = Command::new(&self.instance)
            .arg("--config")
            .arg(&self.config)
            .envs(env.iter().copied())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()
            .with_context(|| format!("starting {}", self.instance.display()))?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = server.try_wait()? {
                bail!(
                    "the instance exited at start ({status}); see {}",
                    self.log.display()
                );
            }
            if let Ok((200, _)) = self.get("/health") {
                break;
            }
            if Instant::now() > deadline {
                let _ = server.kill();
                bail!("the instance did not answer /health within 30s");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.server = Some(server);
        Ok(())
    }

    /// How the instance ended, once it has, unasked.
    fn exited(&mut self) -> Result<ExitStatus> {
        let mut server = self.server.take().ok_or_else(|| anyhow!("not running"))?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = server.try_wait()? {
                return Ok(status);
            }
            if Instant::now() > deadline {
                let _ = server.kill();
                bail!("the instance did not end within 30s");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// SIGTERM, as `systemctl stop` sends; the instance must exit 0.
    fn stop(&mut self) -> Result<()> {
        let mut server = self.server.take().ok_or_else(|| anyhow!("not running"))?;
        command_ok(Command::new("kill").args(["-TERM", &server.id().to_string()]))?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = server.try_wait()? {
                ensure!(status.success(), "the instance stopped with {status}");
                return Ok(());
            }
            if Instant::now() > deadline {
                let _ = server.kill();
                bail!("the instance did not stop within 30s of SIGTERM");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A GET with the path as given, not normalized: `(status, body)`.
    fn get(&self, path: &str) -> Result<(u16, String)> {
        let mut s = TcpStream::connect(("127.0.0.1", self.port))?;
        s.set_read_timeout(Some(DEADLINE))?;
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )?;
        let mut text = String::new();
        s.read_to_string(&mut text)?;
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| anyhow!("no status in {text:?}"))?;
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        Ok((status, body))
    }

    /// A POST of `body` to `path`, sent as given, not normalized, and signed
    /// by the owner over `signed`: `(status, body)`.
    fn signed_post(&self, path: &str, signed: &str, body: &[u8]) -> Result<(u16, String)> {
        let req = levcs_protocol::auth::AuthRequest {
            method: "POST",
            path_with_query: signed,
            body,
        };
        let (key, ts, nonce, sig) =
            levcs_protocol::auth::sign_request(&self.secret("owner")?, &req)?;
        let mut s = TcpStream::connect(("127.0.0.1", self.port))?;
        s.set_read_timeout(Some(DEADLINE))?;
        write!(
            s,
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
             LeVCS-Key: {key}\r\nLeVCS-Timestamp: {ts}\r\nLeVCS-Nonce: {nonce}\r\n\
             LeVCS-Signature: {sig}\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        )?;
        s.write_all(body)?;
        let mut text = String::new();
        s.read_to_string(&mut text)?;
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| anyhow!("no status in {text:?}"))?;
        Ok((
            status,
            text.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
        ))
    }

    /// A push of `objects` moving main from `old` to `new`, signed by the
    /// owner: the refusal it gets, as `(status, message)`.
    fn push(
        &self,
        old: Option<ObjectId>,
        new: ObjectId,
        objects: &[Vec<u8>],
    ) -> Result<(u16, String)> {
        match self.send(&[("refs/branches/main", old, new)], objects)? {
            Ok(()) => bail!("the push was accepted"),
            Err(ClientError::Server { status, body }) => Ok((status, body)),
            Err(e) => Err(e.into()),
        }
    }

    /// A push of `objects` with `updates` (ref, old, new), signed by the
    /// owner, and how the instance took it.
    fn send(
        &self,
        updates: &[(&str, Option<ObjectId>, ObjectId)],
        objects: &[Vec<u8>],
    ) -> Result<std::result::Result<(), ClientError>> {
        let mut pack = Pack::new();
        for bytes in objects {
            pack.push(bytes[4], bytes.clone());
        }
        let manifest = PushManifest {
            updates: updates
                .iter()
                .map(|(name, old, new)| PushUpdate {
                    r#ref: (*name).into(),
                    old_hash: old.map(|o| o.to_hex()),
                    new_hash: new.to_hex(),
                })
                .collect(),
            authority_hash: self.current()?.to_hex(),
            timestamp: now_micros(),
            force: false,
        };
        Ok(Client::new(&self.base).push(&self.secret("owner")?, &self.repo_id, &pack, &manifest))
    }

    /// `name`, one of the scripts in `deploy/` as this gate was built
    /// with them, run with `args` and the gate's levcs.
    fn script_ran(
        &self,
        name: &str,
        args: &[&Path],
        env: &[(&str, &std::ffi::OsStr)],
    ) -> Result<Ran> {
        let text = match name {
            "levcs-backup" => BACKUP_SCRIPT,
            "levcs-restore" => RESTORE_SCRIPT,
            _ => bail!("no script {name}"),
        };
        let path = self.dir.join(name);
        if !path.exists() {
            std::fs::write(&path, text)?;
        }
        run(Command::new("sh")
            .arg(&path)
            .args(args)
            .env("LEVCS", &self.levcs)
            .envs(env.iter().copied()))
    }

    /// [`Self::script_ran`], which must succeed.
    fn script(&self, name: &str, args: &[&Path]) -> Result<()> {
        let ran = self.script_ran(name, args, &[])?;
        ensure!(ran.status.success(), "{name} ({}): {}", ran.status, ran.out);
        Ok(())
    }

    // ---- what the instance holds ----

    fn repos(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.root)? {
            out.push(e?.file_name().to_string_lossy().into_owned());
        }
        out.sort();
        Ok(out)
    }

    fn only_repo(&self) -> Result<String> {
        let repos = self.repos()?;
        ensure!(repos.len() == 1, "the instance holds {repos:?}");
        Ok(repos[0].clone())
    }

    fn main(&self) -> Result<ObjectId> {
        let info = Client::new(&self.base).repo_info(&self.repo_id)?;
        let hex = info
            .branches
            .get("main")
            .ok_or_else(|| anyhow!("the instance has no main"))?;
        Ok(ObjectId::from_hex(hex)?)
    }

    fn current(&self) -> Result<ObjectId> {
        let info = Client::new(&self.base).repo_info(&self.repo_id)?;
        Ok(ObjectId::from_hex(&info.current_authority)?)
    }

    /// The shared repository's first commit, from the first workspace.
    fn first_commit(&self) -> Result<ObjectId> {
        let repo = Repository::discover(self.dir.join("a"))?;
        let mut id = repo
            .refs
            .read("refs/branches/main")?
            .ok_or_else(|| anyhow!("a has no main"))?;
        loop {
            let c = Commit::from_signed(&repo.read_signed(id)?)?;
            match c.parents.first() {
                Some(p) => id = *p,
                None => return Ok(id),
            }
        }
    }

    fn clone_and_verify(&self, name: &str) -> Result<()> {
        self.levcs(
            &self.dir,
            &["clone", &self.repo_id, name, "--from", &self.base],
        )?;
        self.levcs(&self.dir.join(name), &["verify"])?;
        ensure!(
            read_ref(&self.dir.join(name), "refs/branches/main")? == self.main()?,
            "the clone's main is not the instance's"
        );
        Ok(())
    }

    // ---- the CLI ----

    fn levcs_ran(&self, cwd: &Path, args: &[&str]) -> Result<Ran> {
        run(Command::new(&self.levcs)
            .args(args)
            .current_dir(cwd)
            .env("XDG_CONFIG_HOME", &self.xdg))
    }

    /// `levcs args` in `cwd`, which must succeed: what it wrote.
    fn levcs(&self, cwd: &Path, args: &[&str]) -> Result<String> {
        let ran = self.levcs_ran(cwd, args)?;
        ensure!(
            ran.status.success(),
            "levcs {} ({}): {}",
            args.join(" "),
            ran.status,
            ran.out
        );
        Ok(ran.out)
    }

    fn secret(&self, label: &str) -> Result<SecretKey> {
        Ok(
            Keychain::load_or_default(&self.xdg.join("levcs/keys.toml"))?.secret(label, || {
                Err(levcs_identity::error::IdentityError::Other(
                    "the gate's keys are not encrypted".into(),
                ))
            })?,
        )
    }
}

/// A commit of `files` on `parent`, citing `authority`, signed by `sk`: its
/// id, and its objects as a pack carries them, blobs first, the commit last.
fn commit(
    sk: &SecretKey,
    authority: ObjectId,
    parent: Option<ObjectId>,
    files: &[(&str, &[u8])],
) -> Result<(ObjectId, Vec<Vec<u8>>)> {
    let mut objects = Vec::new();
    let mut tree = Tree::new();
    for (name, bytes) in files {
        let blob = Blob::new(bytes.to_vec()).serialize();
        tree.entries.push(TreeEntry {
            name: (*name).into(),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: levcs_core::blake3_hash(&blob),
        });
        objects.push(blob);
    }
    tree.sort_and_validate()?;
    let tree_bytes = tree.serialize();
    let commit = Commit {
        tree: levcs_core::blake3_hash(&tree_bytes),
        parents: parent.into_iter().collect(),
        authority,
        author_key: sk.public().0,
        timestamp_micros: now_micros(),
        flags: CommitFlags::NONE,
        message: "made by levcs-gate".into(),
    };
    objects.push(tree_bytes);
    let signed = sign_commit(commit, sk)?.serialize();
    let id = levcs_core::blake3_hash(&signed);
    objects.push(signed);
    Ok((id, objects))
}

/// Run `cmd` to completion, within [`DEADLINE`].
fn run(cmd: &mut Command) -> Result<Ran> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {cmd:?}"))?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let err = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{cmd:?} took more than {}s", DEADLINE.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = format!(
        "{}{}",
        out.join().unwrap_or_default(),
        err.join().unwrap_or_default()
    );
    Ok(Ran { status, out })
}

fn command_ok(cmd: &mut Command) -> Result<()> {
    let ran = run(cmd)?;
    ensure!(ran.status.success(), "{cmd:?}: {}: {}", ran.status, ran.out);
    Ok(())
}

/// The first `sh` block under `### heading` in `deploy/README.md`, as
/// the gate was built with it.
fn guide_block(heading: &str) -> Result<String> {
    let section = GUIDE
        .split_once(&format!("### {heading}\n"))
        .ok_or_else(|| anyhow!("no section {heading:?} in deploy/README.md"))?
        .1;
    let block = section
        .split_once("```sh\n")
        .and_then(|(_, rest)| rest.split_once("```"))
        .ok_or_else(|| anyhow!("no sh block under {heading:?} in deploy/README.md"))?
        .0;
    Ok(block.to_string())
}

/// `name`'s value in the repository at `work`.
fn read_ref(work: &Path, name: &str) -> Result<ObjectId> {
    let text = std::fs::read_to_string(work.join(".levcs").join(name))
        .with_context(|| format!("{name} in {}", work.display()))?;
    Ok(ObjectId::from_hex(text.trim())?)
}

fn entries(dir: &Path) -> Result<Vec<String>> {
    let mut out: Vec<String> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    out.sort();
    Ok(out)
}

/// `given`, or `name` beside this binary, or `name` on PATH.
fn binary(given: Option<PathBuf>, name: &str) -> Result<PathBuf> {
    if let Some(path) = given {
        ensure!(path.is_file(), "{} is not a file", path.display());
        return Ok(path);
    }
    if let Some(beside) = std::env::current_exe()?
        .parent()
        .map(|dir| dir.join(name))
        .filter(|p| p.is_file())
    {
        return Ok(beside);
    }
    on_path(name).ok_or_else(|| {
        anyhow!(
            "no {name} beside levcs-gate or on PATH; name it with --{}",
            flag(name)
        )
    })
}

/// `name` in a directory on PATH.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

fn flag(name: &str) -> &str {
    if name == "levcs" {
        "levcs"
    } else {
        "instance"
    }
}

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}
