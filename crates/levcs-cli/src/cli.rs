//! clap command tree.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "levcs", version, about = "LeVCS: federated, memory-safe VCS")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a new repository.
    Init(InitArgs),
    /// Mark files as tracked.
    Track(TrackArgs),
    /// Stop tracking files.
    Forget(ForgetArgs),
    /// Create a new commit.
    Commit(CommitArgs),
    /// Reconstruct files from a commit/release/cache.
    Construct(ConstructArgs),
    /// Show changes between working tree and a commit.
    Diff(DiffArgs),
    /// Manage branches.
    Branch(BranchArgs),
    /// Merge a branch into the current branch.
    Merge(MergeArgs),
    /// Declare a release.
    Release(ReleaseArgs),
    /// Manage cached working-tree states.
    Cache(CacheArgs),
    /// Show working-tree status.
    Status,
    /// Show commit history.
    Log(LogArgs),
    /// Print the absolute path of the repository root.
    Root,
    /// Verify every object reachable from any ref, and the authority rules
    /// over all history. Exits 1 if anything is invalid, and 4 if history is
    /// valid but on an authority lineage that conflicts with this one.
    Verify,
    /// Garbage-collect unreachable objects.
    Gc(GcArgs),
    /// Manage the user's keychain.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Manage the repository's authority file.
    #[command(subcommand)]
    Authority(AuthorityCmd),
    /// Manage known instances.
    Instance(InstanceArgs),
    /// Push refs to the active instance.
    Push(PushArgs),
    /// Fetch the active instance's branches, checked, into
    /// refs/remote/origin/.
    Pull(PullArgs),
    /// Clone a repository from an instance into a new workspace of it.
    Clone(CloneArgs),
    /// Fork a repository.
    Fork(ForkArgs),
    /// Inspect a remote repository without pulling.
    Inspect(InspectArgs),
    /// Direct peer-to-peer transfer (sender side).
    Deploy(DeployArgs),
    /// Direct peer-to-peer transfer (receiver side). Refused until it
    /// checks what it receives.
    Dial(DialArgs),
    /// Move a repository to a new instance, preserving repo_id and history (§5.7).
    Migrate(MigrateArgs),
}

// ---------- repository commands ----------

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Key label to use as initial owner; created if absent.
    #[arg(long)]
    pub key: Option<String>,
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct TrackArgs {
    /// Track all files in the working tree.
    #[arg(long)]
    pub all: bool,
    pub paths: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ForgetArgs {
    /// Also delete the file from disk. Off by default: `forget` means stop
    /// tracking, and only tracked files can be named, so anything deleted
    /// here is recoverable from history.
    #[arg(long)]
    pub delete: bool,
    pub paths: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CommitArgs {
    #[arg(short, long)]
    pub message: Option<String>,
    #[arg(long)]
    pub key: Option<String>,
    /// Commit every tracked file. This is the default; the flag is the
    /// explicit spelling of it, and cannot be combined with paths.
    #[arg(long, conflicts_with = "paths")]
    pub all: bool,
    /// Restrict the commit to these files or directories. Everything else
    /// keeps the content it has in HEAD and stays uncommitted.
    pub paths: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ConstructArgs {
    pub hash: Option<String>,
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub release: bool,
    pub paths: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    #[arg(long)]
    pub release: bool,
    pub commit: Option<String>,
    pub paths: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct BranchArgs {
    #[arg(long)]
    pub list: bool,
    #[arg(long)]
    pub create: Option<String>,
    #[arg(long)]
    pub switch: Option<String>,
    #[arg(long)]
    pub delete: Option<String>,
    pub from: Option<String>,
    /// The key that creating or deleting a branch publishes under, in a
    /// repository with no instance. Needed when the keychain holds several.
    #[arg(long)]
    pub key: Option<String>,
    /// With --delete: delete a branch whose commits no other ref reaches,
    /// which unpublishes them. Needs a maintainer.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct MergeArgs {
    #[arg(long)]
    pub review: bool,
    #[arg(long)]
    pub abort: bool,
    #[arg(long)]
    pub explain: bool,
    #[arg(long = "no-auto")]
    pub no_auto: bool,
    /// Output format. `text` (default) emits human-readable lines on
    /// stderr/stdout. `json` emits one structured JSON object on stdout
    /// per §6.7 — useful for scripting and CI.
    #[arg(long = "format", default_value = "text")]
    pub format: String,
    #[arg(long)]
    pub key: Option<String>,
    pub branch: Option<String>,
}

#[derive(Args, Debug)]
pub struct ReleaseArgs {
    pub label: String,
    #[arg(short, long)]
    pub message: Option<String>,
    #[arg(long)]
    pub key: Option<String>,
}

#[derive(Args, Debug)]
pub struct CacheArgs {
    #[arg(long)]
    pub save: bool,
    #[arg(short, long)]
    pub message: Option<String>,
    #[arg(long)]
    pub list: bool,
    #[arg(long)]
    pub restore: Option<String>,
    #[arg(long)]
    pub drop: Option<String>,
}

#[derive(Args, Debug)]
pub struct LogArgs {
    #[arg(long)]
    pub release: bool,
    #[arg(long)]
    pub since: Option<String>,
}

#[derive(Args, Debug)]
pub struct GcArgs {
    #[arg(long)]
    pub aggressive: bool,
    /// Grace period in days. Loose objects modified within this window
    /// are kept regardless of reachability — they may belong to an
    /// in-progress operation that has written the object but hasn't
    /// linked it from any ref yet (§4.2.2). Default 14 days.
    #[arg(long = "grace-days", default_value = "14")]
    pub grace_days: u64,
}

// ---------- identity commands ----------

#[derive(Subcommand, Debug)]
pub enum KeyCmd {
    Generate {
        label: String,
        #[arg(long)]
        encrypt: bool,
    },
    List,
    Show {
        label: String,
    },
    Export {
        label: String,
        path: PathBuf,
    },
    Import {
        label: String,
        path: PathBuf,
    },
    Remove {
        label: String,
    },
    Rename {
        old: String,
        new: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthorityCmd {
    Show,
    List,
    Add {
        key: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        handle: Option<String>,
        #[arg(long = "signing-key")]
        signing_key: Option<String>,
    },
    Remove {
        key: String,
        #[arg(long = "signing-key")]
        signing_key: Option<String>,
    },
    Promote {
        key: String,
        #[arg(long)]
        role: String,
        #[arg(long = "signing-key")]
        signing_key: Option<String>,
    },
}

// ---------- federation commands ----------

#[derive(Args, Debug)]
pub struct InstanceArgs {
    #[arg(long)]
    pub set: Option<String>,
    #[arg(long)]
    pub info: bool,
    #[arg(long)]
    pub add: Option<String>,
    #[arg(long)]
    pub list: bool,
    #[arg(long)]
    pub remove: Option<String>,
}

#[derive(Args, Debug)]
pub struct PushArgs {
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub force: bool,
    /// Measure the push, against the instance's limits, and send nothing.
    #[arg(long)]
    pub dry_run: bool,
    pub refs: Vec<String>,
}

#[derive(Args, Debug)]
pub struct PullArgs {
    /// Sign reads with this key: a private repository is served only to its
    /// members.
    #[arg(long)]
    pub key: Option<String>,
    pub refs: Vec<String>,
}

#[derive(Args, Debug)]
pub struct CloneArgs {
    /// The repository's id: 64 hex digits.
    pub repo_id: String,
    /// Where to put it (defaults to the id's first 8 digits).
    pub path: Option<PathBuf>,
    /// The instance's URL (defaults to the active instance).
    #[arg(long)]
    pub from: Option<String>,
    /// Sign reads with this key: a private repository is served only to its
    /// members.
    #[arg(long)]
    pub key: Option<String>,
}

#[derive(Args, Debug)]
pub struct ForkArgs {
    pub repo_id: String,
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub key: Option<String>,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    pub repo_id: String,
    #[arg(long)]
    pub from: Option<String>,
    pub path: Option<String>,
}

#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Ed25519 public key of the recipient who is permitted to dial in.
    pub recipient_key: String,
    /// Send only release refs (and their reachable closure). Without this
    /// flag, branches and releases are both included.
    #[arg(long)]
    pub release: bool,
    /// Identity key the deployer signs with (defaults to active key).
    #[arg(long)]
    pub key: Option<String>,
    /// Address to bind for incoming dialers. Defaults to 0.0.0.0:0 (any
    /// free port; the bound address is printed before listening).
    #[arg(long, default_value = "0.0.0.0:0")]
    pub listen: String,
    /// Repository path to deploy from (defaults to the current directory).
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DialArgs {
    /// host:port the sender's deployer is listening on.
    pub sender_host: String,
    /// Ed25519 public key the sender is expected to sign with.
    pub sender_key: String,
    /// Identity key the dialer authenticates with (defaults to active).
    #[arg(long)]
    pub key: Option<String>,
    /// Destination directory for the received repository (defaults to
    /// `<repo_id_prefix>` in the current working directory).
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// Base URL of the destination instance (including /levcs/v1).
    pub to: String,
    /// Identity key to sign init/push requests.
    #[arg(long)]
    pub key: Option<String>,
    /// After a successful migration, set this URL as the active instance
    /// pointer for the local repository so subsequent push/pull use it.
    #[arg(long)]
    pub set_active: bool,
}
