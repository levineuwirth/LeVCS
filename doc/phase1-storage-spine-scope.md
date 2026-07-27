# Phase 1 scope — storage engine spine

Companion to `doc/instance-throughput-rewrite-plan.md` §12 "Phase 1 — storage engine spine".
The rewrite plan remains authoritative. Where this document is more specific, it is the
lead's Phase 1 realization of the plan; where it appears to contradict the plan, the plan
wins and this document is defective.

Status: **D0 landed; Wave A unblocked.** Section 9's decisions were all resolved on
2026-07-24 and are recorded there with their conditions. Contract review 2026-07-24-B
(sections 9.1 and 9.2) has been applied to `bench/result-schema.json` and
`bench/reference-hardware.toml` and recorded in the plan document. `crates/levcs-store`
exists with the frozen API, the ownership split, the durability funnel, the failpoint
registry, and the drive seam; the gate is `scripts/check-phase1.sh`.

What D0 shipped, against section 2:

- The public API of 2.2 compiling and returning `StoreError::NotImplemented`, with
  `AppliedRef` re-exported from the protocol crate and `PrivilegedConstruction` gated on the
  `store-privileged` cargo feature rather than reachable from an engine.
- `sys.rs` as the sole durability funnel, with counters and the fault set of 4-A3
  deliverable 4; `failpoints.rs` in compiler-enforced correspondence with the frozen oracle,
  including the wave partition pinned by name.
- `format.rs` and `drive.rs` with lead-authored types and signatures and `unimplemented!()`
  bodies, so A1 fills them while A2 and A3 work against stable shapes.
- `options.rs` refusing every invalid configuration, delegating the replay-retention
  relation to the frozen protocol function so the store cannot disagree with it.
- Eight D0 contract tests, of which two are grep-based structural guards that were verified
  by injecting real violations and observing them fail, not by assuming they work.

### Scope review 2026-07-24-C

The first draft was reviewed before D0. The review found one structural gap (A3 had no way
to drive anything in Wave A), one internal inconsistency (the `CURRENT` install could not
be expressed by the `sys.rs` funnel, and recovery's manifest fallback had nothing to read),
and a needed amendment to the §9.1 resolution. All are folded in here:

- 2.1/2.3/4-A1/4-A3: a feature-gated journal-level **drive API** that A1 implements and A3
  consumes, so the crash matrix and the P1-micro benchmark are runnable in Wave A rather
  than blocked on B1's `submit`.
- 4-A3: the Wave A / Wave B failpoint partition is now given **by name**, per row, with the
  one boundary row called out; the earlier draft gave a count, and the count was wrong.
- 3.5/3.8: durable versioned `manifests/<generation>.manifest` alongside `CURRENT`, and
  `rename_replace` added to the syscall funnel. `CURRENT` alone is a single mutable name;
  "select the newest checksum-valid `CURRENT`" and A2's "corrupt `CURRENT` with a valid
  predecessor" both presupposed a history the layout never kept.
- 3.3: `flags` and every padding region are now pinned by completeness conditions. Without
  them, 2^32 flag values produce a "complete" frame the writer never wrote — precisely the
  byte sequence the section 5 charter directs the reviewer to construct.
- 9.1: the flag split is per-flag, not blanket. `durability_fence_before_response` and
  `typed_ref_cas` remain true at P2; declaring the fence flag false would gut the meaning of
  the bundle that exists to certify the fence.
- 9.3/4-A3: `group_failpoint_expectation` returns a **contiguous adopted prefix**, not a
  per-frame classification, so the matrix can distinguish a correct stop-at-first-hole from
  an incorrect adopt-past-a-hole.
- 1: the dependency claim is restated as "no direct dependency and no calls into"
  `levcs-identity`; the link edge is transitive through `levcs-protocol` and the flat claim
  was false.
- 8.1/8.2/9.4: fence-rate, free-space, and `payload_digest` cost figures corrected.

A second pass folded in four residuals — the charter's stale condition count (5),
`root_uuid`'s file list (3.1), the two new manifest-referent recovery cases (4-A2), and the
overstated preallocation claim (3.2) — and recorded the rulings on 9.1–9.5 and the
`WriterPanicAfterFence` wave assignment.

## 0. Standing and preconditions

Phase 0 is complete and amended by contract review 2026-07-24-A. Phase 1 binds to the
amended artifacts:

- `levcs-protocol::v2` — `CommittedTransactionV1`, `TransactionEvidenceV1`,
  `SignedCommittedTransactionV1`, `CommitReceiptV1`, `TransactionStatusV1`, `AppliedRefV1`,
  `TypedRefCas`, `RefTarget`, `SourceKindV1`, `StagedProjectionInstallV1`,
  `receipt_visible_until`, `status_tombstone_until`.
- `levcs-protocol::oracle` — `AppendFailpoint`, `append_publication_expectation`,
  `RecoveryOutcome`, `resolve_ambiguous_tail`, `two_root_status_read`, `public_status_read`,
  `coalescing_decision`, `deadline_expectation`, `recovered_receipt_visibility`,
  `ExternalAckJournal`, `verify_exact_restore`.
- `bench/workloads/small-commit.toml`, `bench/result-schema.json`,
  `bench/reference-hardware.toml`.

Phase 1 may not change any of these without a recorded contract review. Section 9.1
identifies one place where it appears a review is already required.

## 1. Scope boundary

### In scope

One new workspace crate, `crates/levcs-store`, containing the durable transaction spine:
frame format, journal append and group fence, segment sealing and rotation, recovery,
object/ref/receipt index and checkpoints, namespace/transaction/snapshot engine, bounded
projection staging, and the store-level benchmark and crash harness.

### Out of scope for Phase 1

- Any edit to `crates/levcs-instance`, `crates/levcs-client`, `crates/levcs-cli`. The v1
  instance keeps working, untouched, on the v1 layout for the whole phase.
- HTTP, request authentication, replay guard, admission, Pack streaming, graph/identity/
  policy validation. Those are Phase 2; the store consumes an already-`ValidatedTransaction`.
- `compaction.rs` and `backup.rs` (Phase 4), `migration.rs` (Phase 2 `InstanceMigrator`).
  Phase 1 must leave explicit, tested seams for them — see 3.5 and 6.1 — but implements
  neither.
- Federation trust. The store takes an injected `CommitEvidenceSigner` and never decides
  who may sign.

### Dependency direction

`levcs-store` depends on `levcs-core` (object IDs, raw framing) and on `levcs-protocol`
(the frozen logical contracts it must construct and embed). It takes **no direct dependency
on and makes no call into** `levcs-identity`, and does not depend on `levcs-merge` or
`levcs-instance` at all.

`levcs-identity` is nonetheless present in the build graph: `levcs-protocol` depends on it.
The invariant Phase 1 enforces is therefore about calls, not about the link edge — no
`levcs_identity::` path may appear anywhere in `levcs-store`, enforced by a D0 test that
greps the crate source. The plan forbids the store from making identity-role decisions; it
does not and could not forbid a transitive edge.

This is a deliberate reading of §5.1's "depends on `levcs-core` … but contains no HTTP,
identity-role, merge-policy, or federation decisions". The store cannot avoid
`levcs-protocol`: §5.2 requires the shard sequencer itself to assign `repo_sequence` and
`previous_event_digest`, compute the event and state digests, and place a signed
`CommittedTransactionV1` in the frame. It can and must avoid interpreting evidence beyond
`source_kind` and its digest, and avoid all signature *verification*.

## 2. Lead deliverable D0 — the sealed skeleton

D0 blocks all three Wave A packages. It is a single lead commit that compiles, passes
`cargo test --workspace`, and contains no agent-owned implementation.

### 2.1 File ownership matrix

No two agents may edit the same file. A package that needs a change in another package's
file files a lead-arbitrated interface change request; it does not edit.

| Path | Owner | Phase 1 state |
|---|---|---|
| `crates/levcs-store/Cargo.toml` | Lead | D0 |
| `crates/levcs-store/src/lib.rs` | Lead | D0 |
| `crates/levcs-store/src/types.rs` | Lead | D0 (ids, `StoreError`, `CommitReceipt`, status) |
| `crates/levcs-store/src/options.rs` | Lead | D0 (`StoreOptions`, validation) |
| `crates/levcs-store/src/sys.rs` | Lead | D0 (durability syscall shim + counters + fault hooks) |
| `crates/levcs-store/src/failpoints.rs` | Lead | D0 (registry, 1:1 with `oracle::AppendFailpoint`) |
| `crates/levcs-store/src/format.rs` | Lead types / **A1** bodies | D0 signatures, A1 implementation |
| `crates/levcs-store/src/journal.rs` | **A1 JournalWriter** | Wave A |
| `crates/levcs-store/src/segment.rs` | **A1 JournalWriter** | Wave A |
| `crates/levcs-store/src/drive.rs` | Lead signatures / **A1** bodies | D0 signatures, A1 implementation |
| `crates/levcs-store/src/index.rs` | **A2 RecoveryIndex** | Wave A |
| `crates/levcs-store/src/checkpoint.rs` | **A2 RecoveryIndex** | Wave A |
| `crates/levcs-store/src/recovery.rs` | **A2 RecoveryIndex** | Wave A |
| `crates/levcs-store/benches/durable_ingest.rs` | **A3 StoreHarness** | Wave A |
| `crates/levcs-store/src/bin/store-bench.rs` | **A3 StoreHarness** | Wave A |
| `crates/levcs-store/src/bin/store-crash-driver.rs` | **A3 StoreHarness** | Wave A |
| `crates/levcs-store/tests/support/**` | **A3 StoreHarness** | Wave A |
| `crates/levcs-store/tests/frame_golden.rs` | **A1** | Wave A |
| `crates/levcs-store/tests/fixtures/phase1-frames.json` | **A1** | Wave A |
| `crates/levcs-store/examples/phase1_frame_golden.rs` | **A1** | Wave A |
| `crates/levcs-store/tests/recovery_*.rs` | **A2** | Wave A |
| `crates/levcs-store/tests/crash_matrix.rs` | **A3** | Wave A |
| `crates/levcs-store/tests/fixtures/phase1-failpoints.json` | **A3** | Wave A |
| `crates/levcs-store/src/engine.rs` | **B1 NamespaceTxn** | Wave B |
| `crates/levcs-store/src/transaction.rs` | **B1 NamespaceTxn** | Wave B |
| `crates/levcs-store/src/snapshot.rs` | **B1 NamespaceTxn** | Wave B |
| `crates/levcs-store/src/staging.rs` | **B1 NamespaceTxn** | Wave B |
| `scripts/verify-store-recovery.sh` | **A3** | Wave A |
| `scripts/check-phase1.sh` | Lead | Wave A freeze gate |
| `Cargo.toml`, `Cargo.lock` | Lead | D0 |

`format.rs` and `drive.rs` are the two shared files. The lead writes their type
definitions, constants, domain strings, and function signatures in D0 with
`unimplemented!()` bodies; A1 fills the bodies; A2 consumes `format.rs` read-only and A3
consumes `drive.rs` read-only. This is what keeps the three Wave A packages genuinely
parallel.

`drive.rs` exists because of a gap in the first draft: A3's `store-crash-driver` and
`store-bench` are separate binary crates that see only the public API, and the public API's
`submit` returns `NotImplemented` until B1 writes `engine.rs` in Wave B. As first written,
neither of A3's Wave A acceptance criteria was reachable. `drive.rs` is a `#[doc(hidden)]`,
`store-internals`-feature-gated journal-level API — open a shard journal, append a
pre-encoded frame group, fence, seal, and reopen through recovery — with no engine, status
root, sequencer, or signer. It is a test and benchmark seam, never compiled into a release
binary, and B1 does not build on it.

### 2.2 Frozen public API

D0 lands §5.1's API verbatim, compiling, with every method returning
`Err(StoreError::NotImplemented)`. Freezing signatures before implementation is what lets
A3 write the benchmark and crash harness against the real API in Wave A rather than
retrofitting it in Wave B.

```rust
pub struct NamespaceId(pub [u8; 32]);      // == repo_id
pub struct OperationId(pub [u8; 16]);

pub struct StoreEngine { /* private */ }
pub struct RepoSnapshot { /* immutable logical state */ }
pub struct ValidatedTransaction { /* sealed */ }
pub struct CheckpointLease { /* private */ }

pub struct CommitReceipt {
    pub operation_id: OperationId,
    pub repo_sequence: u64,
    pub current_authority: ObjectId,
    pub refs: Vec<AppliedRef>,
    pub objects_new: u64,
}

pub enum PendingPhase { Receiving, Validating, Queued, Sequenced }

pub enum TransactionStatus {
    Committed(CommitReceipt),
    Pending   { operation_digest: ObjectId, retry_until_micros: i64, phase: PendingPhase },
    Resolving { operation_digest: ObjectId, retry_until_micros: i64, shard_sequence: Option<u64> },
    Expired   { operation_digest: ObjectId, retry_until_micros: i64, tombstone_until_micros: i64 },
    Unknown,
}

impl StoreEngine {
    pub fn open(options: StoreOptions) -> Result<Self, StoreError>;
    pub fn snapshot(&self, repo: NamespaceId) -> Result<RepoSnapshot, StoreError>;
    pub async fn submit(&self, txn: ValidatedTransaction) -> Result<CommitReceipt, StoreError>;
    pub fn transaction_status(&self, repo: NamespaceId, operation: OperationId)
        -> Result<TransactionStatus, StoreError>;
    pub fn checkpoint(&self) -> Result<CheckpointLease, StoreError>;
}
```

Also frozen in D0:

```rust
/// Injected by instance composition. The store never decides who may sign.
pub trait CommitEvidenceSigner: Send + Sync {
    fn key_epoch(&self) -> u64;
    fn public_key(&self) -> [u8; 32];
    fn sign_event(&self, event_digest: &ObjectId) -> Result<[u8; 64], SignerError>;
}

/// Privileged construction. Sealed so instance validation, recovery, and
/// (later) migration can build one and nothing else can.
pub struct ValidatedTransactionBuilder { /* private */ }
impl ValidatedTransaction {
    pub fn builder(_: PrivilegedConstruction) -> ValidatedTransactionBuilder;
}
pub struct PrivilegedConstruction(());
```

`PrivilegedConstruction` must **not** be obtainable from a `&StoreEngine`. A
`StoreEngine::privileged()` method would make the seal decorative: anything holding an
engine — which is everything that can call `submit` — could mint one. D0 gates it instead
on the `store-privileged` cargo feature, which only `levcs-instance` (validated ingest),
the crate's own `recovery.rs`, and the Phase 2 migrator enable. A D0 test asserts that
without that feature there is no safe path to a `ValidatedTransaction`.

`CommitReceipt.refs` is `Vec<AppliedRef>` in §5.1 while the frozen protocol type is
`AppliedRefV1`. D0 must pick one and state why. Recommendation: re-export
`levcs_protocol::v2::AppliedRefV1 as AppliedRef`. The receipt crosses the wire in
`CommitReceiptV1`; a parallel store-local type would need a conversion that could silently
disagree with a frozen contract, which is the failure mode contract review 2026-07-24-A was
about.

`StoreError` taxonomy (D0, extended only by the lead):
`NotImplemented`, `Corruption`, `RecoveryRequired`, `ShardPoisoned`, `ReadOnly`,
`FormatMismatch`, `LegacyLayout { migrate_command: String }`, `UnrecognizedLayout`,
`AlreadyLocked`, `Io`, `NoSpace`, `LimitExceeded`, `Conflict`, `NotReady`, `Signer`.

`StoreError` is never used for a normal lifecycle state; that is `TransactionStatus`
(§5.1). D0 adds a compile-visible doc-test asserting this split.

### 2.3 Frozen internal interfaces

`sys.rs` (lead-owned) is the single funnel for every durability-relevant syscall. Nothing
else in the crate may call `File::sync_all`, `sync_data`, `rename`, `unlink`, or open a
directory fd.

```rust
pub(crate) fn write_vectored_all(fd: &File, offset: u64, bufs: &mut [IoSlice]) -> io::Result<()>;
pub(crate) fn fdatasync(fd: &File) -> io::Result<()>;
pub(crate) fn fsync_dir(path: &Path) -> io::Result<()>;
/// renameat2(RENAME_NOREPLACE). For names that must never overwrite: new
/// manifests, segments, checkpoints, index runs, migration/restore siblings.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()>;
/// Plain atomic replacing rename. Required for exactly one thing: the
/// `CURRENT.tmp` -> `CURRENT` pointer install of 3.5, which by definition
/// replaces. Every other call site must use `rename_noreplace`.
pub(crate) fn rename_replace(from: &Path, to: &Path) -> io::Result<()>;
pub(crate) fn pread_exact(fd: &File, offset: u64, buf: &mut [u8]) -> io::Result<()>;
pub(crate) fn preallocate(fd: &File, len: u64) -> io::Result<()>;

/// Per-shard, monotonic, readable from tests.
pub(crate) struct DurabilityCounters {
    pub fdatasync: AtomicU64, pub fsync_dir: AtomicU64,
    pub write_vectored: AtomicU64, pub short_writes: AtomicU64,
    pub bytes_written: AtomicU64,
}
```

The counters are how "no per-object fsync" (Phase 1 exit) becomes a mechanical assertion
rather than a claim: a run of *N* transactions carrying *3N* objects in *G* groups must
show `fdatasync == G` and `fdatasync < N`, never `≈ 3N`.

`failpoints.rs` mirrors `oracle::AppendFailpoint` one-for-one, behind a `failpoints`
cargo feature that is off in release:

```rust
#[cfg(feature = "failpoints")]
pub(crate) fn hit(point: AppendFailpoint) -> FailpointAction; // Continue | Fail | Panic | HardExit
#[cfg(not(feature = "failpoints"))]
#[inline(always)] pub(crate) fn hit(_: AppendFailpoint) -> FailpointAction { FailpointAction::Continue }
```

A D0 test asserts the store's failpoint enum is exhaustively convertible to and from
`oracle::APPEND_PUBLICATION_FAILPOINTS` — a new failpoint in either place breaks the build.

### 2.4 Workspace dependency additions

Added to `[workspace.dependencies]` and to `levcs-store` in D0. Versions are pinned when
D0 lands; `Cargo.lock` is a reviewed artifact per §10.

| Crate | Why | Alternative rejected |
|---|---|---|
| `arc-swap` | §5.1 mandates `ArcSwap<CommittedRoot>`, explicitly not `RwLock<Arc<_>>` | — |
| `crossbeam-channel` | §7 "bounded crossbeam-style channels" to shard threads | `std::sync::mpsc` is unbounded/single-consumer |
| `rustix` | `renameat2(RENAME_NOREPLACE)`, `O_TMPFILE`, `fdatasync`, `fallocate`, `pwritev`, `flock` without hand-rolled `libc` unsafe | raw `libc` (more unsafe surface), `nix` (heavier) |
| `memmap2` | §5.3 memory-mapped immutable index runs | read-based runs; revisit if mmap SIGBUS-on-truncate handling proves worse |
| `hdrhistogram` | §10 HDR-style histograms in the result bundle | — |

Not taken: any third-party Bloom filter (the filter is part of a frozen on-disk format;
`index.rs` implements a documented, seeded, versioned filter in-crate), any serde-based
on-disk encoding (the format is hand-written canonical binary, as in Phase 0).

`tokio` is a dependency only for `submit`'s `async` signature and `oneshot` completion; the
store starts no runtime and does no I/O on a Tokio thread.

### 2.5 Decisions made in D0

**Shard routing.** `shard_index = u16::from_le_bytes([repo_id[0], repo_id[1]]) % shard_count`.
`repo_id` is a BLAKE3 digest, so this is uniform. `shard_count` is written into `FORMAT` at
initialization and is **immutable for the life of the root**; opening with a different
configured `shard_count` is a hard `FormatMismatch` refusal, never a silent reroute.
This is load-bearing: `repo_sequence` and the per-repository event chain are owned by
exactly one shard thread with no cross-shard coordination, and that is only sound while a
repository's shard assignment never moves. Resharding is a future offline tool.

**Shard poisoning is per-shard.** A poisoned shard 0 refuses new mutations for its
repositories; shards 1..N keep committing. Availability is therefore partial, not total,
and the harness must prove it (5.3).

**Frames are byte-identical between journal and sealed segment.** Sealing appends a footer
and renames; it never re-encodes. One golden frame corpus therefore covers both readers.

**Also settled in D0, from scope review 2026-07-24-C:** the `drive.rs` signature set (2.1);
`PrivilegedConstruction` gated on a cargo feature rather than reachable from `&StoreEngine`
(2.2); `CommitReceipt.refs` element type (2.2); the `WriterPanicAfterFence` wave assignment
(4-A3); and `flags`/padding pinning plus `header_digest` coverage (3.2, 3.3), all of which
are frozen-byte or frozen-surface decisions that cannot be deferred into Wave A.

## 3. Physical format specification

This section is the lead's proposal. A1 implements it and owns the golden vectors; the
Wave A freeze gate (section 5) is where it becomes binding. §13 keeps the physical format
internal — nothing outside `levcs-store` may bind to these bytes.

### 3.1 Root layout, FORMAT, LOCK

Exactly §5.2's tree. Additions Phase 1 needs and the plan permits:

```text
<root>/
  FORMAT
  LOCK
  quarantine/<journal_id>-<offset>.tail      # discarded torn tails, forensics only
  staging/<shard>/<session-id>/...
  shards/NN/{active,segments,indexes,checkpoints,manifests,CURRENT}
```

`manifests/<generation>.manifest` is the addition. §5.2 names only `CURRENT`, but `CURRENT`
is a single mutable name, and both §5.2's own "select only a checksum-valid `CURRENT`" and
A2's "corrupt `CURRENT` with a valid predecessor" case require a predecessor to fall back
to. Manifests are therefore durable, immutable, and versioned: each is written under a new
`<generation>` name with `rename_noreplace`, at least `manifest_retain` generations are
kept, and `CURRENT` becomes the atomically replaced pointer naming the active generation.
Recovery reads `CURRENT`; if it is corrupt, or its referenced files fail validation, it
falls back to the newest valid `manifests/<generation>.manifest`. This is additive to the
plan's layout and changes no plan-visible behavior.

`FORMAT` is `{ magic, format_version, storage_version, shard_count, root_uuid,
created_at_micros, checksum }`, written then directory-synced. `root_uuid` binds every
`CURRENT`, manifest, journal, segment, index run, and checkpoint in the root; a file whose
`root_uuid` differs is rejected, which catches a file copied in from another instance.

`LOCK` is held with `flock(LOCK_EX|LOCK_NB)` for process lifetime. Failure is
`AlreadyLocked`, never a wait.

Startup states (§5.2), decided in this order and with no inference:

1. Path absent, or present and empty → initialize v2. Create the tree, write `FORMAT`,
   fsync every new directory and the root's parent.
2. Valid `FORMAT` → open through production recovery (3.8).
3. No `FORMAT`, but the directory matches the legacy signature (≥1 entry of the form
   `<64-hex>/.levcs/`) → `LegacyLayout` carrying the exact
   `levcs-instance migrate-store --source <root> --destination <dest>` string. No writes.
4. Anything else non-empty → `UnrecognizedLayout`. No writes, no probing.

### 3.2 Journal file

`shards/NN/active/<first_shard_sequence>.journal`.

File header (512 bytes, zero-padded, checksummed):
`magic "LVCSJRN\0"`, `storage_version u16`, `header_len u16`, `shard_index u16`, pad,
`root_uuid [16]`, `journal_id [16]` (fresh random per file), `first_shard_sequence u64`,
`preallocated_len u64`, `created_at_micros i64`, `header_digest [32]`.

`header_digest` = `BLAKE3("levcs-journal-header/v1\0" || header_bytes[0..512])` with the
`header_digest` field itself zeroed for the computation. Every byte of the 512 that is not
a named field is padding and **must be zero**; a non-zero padding byte rejects the header.
Leaving reserved space unconstrained is how a format acquires undocumented variants.

The journal is preallocated to `preallocated_len` at creation (`fallocate`, **without**
`FALLOC_FL_KEEP_SIZE`) and directory-synced before its first append. Appends are then
overwrites within an already-sized file, so `fdatasync` never has to persist a file-size
change, and the region past the write cursor reads as zeros.

That is a reduction in metadata work, not an elimination of it: the first write into each
preallocated extent converts it from unwritten to written, which is metadata that
`fdatasync` must and does persist. The benefit is that the conversion happens once per
extent rather than once per append, and that no `i_size` update is ever needed. Under
copy-on-write (9.2) even this is optimistic — btrfs allocates fresh extents per write
regardless of preallocation. Rotation happens when the cursor reaches
`preallocated_len` or the configured segment size, whichever is first.

`journal_id` is in every frame. It is the defense against a frame from a previous
incarnation of a recycled or non-zeroing extent being accepted as a live frame, and it also
catches a segment or journal misfiled under the wrong name in `CURRENT`.

### 3.3 Transaction frame

Header, 176 bytes, all integers little-endian:

| Off | Size | Field |
|---|---|---|
| 0 | 8 | magic `"LVCSFRM\0"` |
| 8 | 2 | `storage_version` (1) |
| 10 | 2 | `header_len` (176) |
| 12 | 4 | `flags` — **must be 0 in storage version 1**; any set bit rejects |
| 16 | 8 | `total_len` — header + payload + padding + trailer |
| 24 | 16 | `journal_id` |
| 40 | 8 | `shard_sequence` |
| 48 | 8 | `repo_sequence` |
| 56 | 32 | `namespace` (`repo_id`) |
| 88 | 16 | `operation_id` |
| 104 | 32 | `operation_digest` |
| 136 | 8 | `payload_len` |
| 144 | 32 | `payload_digest` = `BLAKE3("levcs-frame-payload/v1\0" || payload)` |

Payload — canonical `TransactionFramePayloadV1`, all of §5.2's frame contents:
optional repository-create metadata; either inline new objects (`embedded type, ObjectId,
raw_len, raw bytes` each) or exactly one `StagedProjectionInstallV1` descriptor; the
complete typed ref CAS set; expected/new current authority; canonical
`TransactionEvidenceV1`; canonical `CommittedTransactionV1` plus source key epoch, source
signature, and resulting state digest; deterministic receipt fields.

Padding: zero bytes so that `header_len + payload_len + pad` is a multiple of 8.

Trailer, 48 bytes: magic `"LVCSEND\0"`, `total_len` repeated (u64), then
`frame_digest [32]` = `BLAKE3("levcs-frame/v1\0" || bytes[0 .. total_len-32])`.

A frame is **complete** iff, and only iff, all of the following hold — this is the exact
definition recovery uses and the one an adversarial reviewer should attack first:

1. `total_len ≥ 224`, `total_len % 8 == 0`, and `offset + total_len` is within the
   journal's preallocated length.
2. Header magic and `storage_version` match; `header_len == 176`.
3. `journal_id` equals the containing file's `journal_id`.
4. Trailer magic matches and the trailer's repeated `total_len` equals the header's.
5. `frame_digest` recomputes.
6. `payload_digest` recomputes.
7. `flags == 0`.
8. Every padding byte between the payload and the trailer is zero.

Conditions 7 and 8 are not decoration. Without 7, any of 2^32 `flags` values yields a
frame satisfying every other condition that the writer never produced — exactly the byte
sequence the section 5 charter directs the reviewer to construct, so a format that does not
pin it hands the reviewer a finding by construction. Without 8, the padding is a covert
region that `frame_digest` authenticates but nothing constrains. A future storage version
that wants flags allocates them explicitly and bumps `storage_version`.

**Evaluation order is normative: cheap structural checks before digests.** The numbering
above is a list, not a sequence. `verify_complete` evaluates the length, magic, header-len,
`journal_id`, `flags`, padding, and trailer conditions — all header or fixed-offset reads —
before recomputing `frame_digest` or `payload_digest`, so a malformed frame is rejected
without hashing it. The *set* of complete frames is identical under any order, so this is a
determinism rule rather than a correctness one, but it has a testing consequence: **a
negative test that asserts a specific `FrameError` variant must violate exactly one
condition.** An input violating two conditions may legitimately report either. A2's
independently written reference verifier followed the numbering and A1's follows cost,
which is how the ambiguity surfaced; both accept and reject exactly the same frames.

The frame payload is canonical `TransactionFramePayloadV1`, and `format.rs` must expose at
least `previous_event_digest`, `event_digest`, and `source_kind` from it. Recovery step 9
verifies the per-repository event chain and cannot do so against an opaque `Vec<u8>`.

The trailer exists so that a torn write cannot leave a self-consistent frame: the last
bytes written are the ones that certify the whole.

Considered and rejected: a physical `previous_frame_digest` chain. `shard_sequence`
contiguity plus the per-repository `previous_event_digest` in `CommittedTransactionV1`
already make deletion and reordering detectable, and internal storage is not defended
against an attacker with write access to the root.

### 3.4 Sealing and segments

Sealing converts a full journal into `segments/<generation>-<first>-<last>.seg` without
re-encoding a single frame byte:

1. Stop appending; validate the whole file forward.
2. Append a segment footer: `{ magic "LVCSSEG\0", storage_version, root_uuid, journal_id,
   generation, first/last shard_sequence, frame_count, offset table (shard_sequence →
   offset,len), footer_digest }`.
3. `fdatasync` the file.
4. **`link`** the file into `segments/` under its segment name — not `rename` — and
   `fsync_dir` on `segments/`. The file is now reachable under both names.
5. Install the manifest generation referencing the segment name and swap `CURRENT` (3.5).
6. Only now `unlink` the `active/` name and `fsync_dir` on `active/`.

**Step 4 must link rather than rename, and this is a correctness requirement, not a
preference.** A rename makes the file reachable under exactly one name at every instant. A
crash after the rename and before the manifest install would then leave a valid segment
that no manifest references *and* no active journal to scan — and 3.8 step 2 trusts only
manifest-referenced files, so a fenced, acknowledged prefix would be silently lost. That is
a violation of plan §4 transaction invariant 3. Linking keeps the prefix reachable through
the `active/` name across the entire window; every crash point in 1–6 leaves either the
journal still scannable or a manifest that references the segment, and never neither.

The first draft of this document specified a rename here and additionally told step 5 to
"unlink the old journal name", which a rename has already consumed. A1 found both while
implementing and reported them rather than working around them.

Recovery consequence: after step 4 and before step 6 both names exist, so recovery may find
an `active/` journal whose `journal_id` is already covered by a manifest-referenced segment.
That is a completed seal whose final unlink was lost, not a second copy of the data.
Recovery unlinks the stale active name and proceeds from the manifest; it must not replay
those frames twice.

Footer presence distinguishes sealed from active. `segment.rs` reads a sealed segment by
offset table plus bounded `pread`, with an LRU open-fd cache under a configured ceiling.
It can also read an unsealed journal by forward scan, which is what recovery uses.

### 3.5 CURRENT manifest

`{ magic, storage_version, root_uuid, generation, base_generation,
retained_tail_ranges[(generation, first_seq, last_seq, filename)],
index_runs[(generation, filename)], checkpoints[(shard_sequence, filename)],
committed_shard_sequence, digest }`.

Install, extending §5.2's sequence with the durable manifest history of 3.1:

```text
1  write manifests/<generation>.manifest.tmp   (new generation, never an existing name)
2  fdatasync it
3  rename_noreplace -> manifests/<generation>.manifest
4  fsync_dir manifests/
5  write CURRENT.tmp naming <generation>; fdatasync it
6  rename_replace  -> CURRENT           <-- the one replacing rename in the crate
7  fsync_dir the shard directory
8  only now unlink superseded names, then fsync_dir their directories
9  retain >= manifest_retain generations in manifests/ before unlinking older ones
```

Step 6 is the visibility boundary for the manifest. Steps 1–4 are what give recovery
something to fall back to when `CURRENT` or its referenced files do not validate; the first
draft's single-`CURRENT` layout had no such predecessor, which made both §5.2's "select
only a checksum-valid `CURRENT`" and A2's corrupt-`CURRENT` acceptance case unsatisfiable.

Compaction (Phase 4) reuses this install path unchanged — the manifest already carries
`base_generation` so that a `BaselineStateV1` base plus retained tails is representable in
Phase 1's format without a format change. Phase 1 always writes `base_generation = 0` and
no baseline; leaving the field is the seam.

### 3.6 Checkpoints and index runs

`checkpoints/<shard_sequence>.checkpoint` is derived state through that sequence:
namespace catalog (repo_id, genesis authority, lifecycle, storage mode), per-repository
`repo_sequence` + `previous_event_digest` + typed ref state + current/genesis authority,
shard committed sequence, the **active `journal_id` and journal offset** the checkpoint
resumes replay from, and the retained operation/receipt table with
`first_receipt_visibility_micros`, `retry_until_micros`, `receipt_visible_until`.

The resume point is load-bearing and was missing from the first draft. §5.3 bounds "replay
bytes/frames since the newest durable checkpoint" and 3.8 step 5 scans "from the checkpoint
offset"; without the journal identity and offset recorded here, replay restarts at the
journal header on every open, which is exactly the unbounded scan §5.3 forbids. The
`journal_id` accompanies the offset because an offset alone is meaningless once the
journal has rotated.

`first_receipt_visibility_micros` is optional on the wire with an explicit presence byte,
never a sentinel value. A sentinel would make "not yet captured" indistinguishable from a
legal timestamp and would silently break the step 10 promotion rule.
Checksummed, versioned, `root_uuid`-bound. At least two independently validated
generations are retained; if both fail validation, startup enters explicit offline rebuild
mode rather than an unbounded scan (§5.3).

`indexes/<generation>.idx` is an immutable sorted run over
`(namespace, ObjectId) -> (segment_generation, offset, len, ObjectType, shard_sequence)`,
with a versioned seeded Bloom filter in its header. Runs are mmapped. The active in-memory
delta has hard entry and byte ceilings from `StoreOptions`; crossing the soft watermark
backpressures, and the shard synchronously seals and checkpoints at the hard ceiling.

Entry-size budget, which §13 requires be reported: `namespace` is factored out per run
section, leaving 32 (ObjectId) + 15 (packed location) = 47 bytes per object. See 8.2.

**Measured (A2, Wave A):** 47.00 bytes/entry packed, matching the budget exactly; 48.29
bytes/entry for a whole run including header, filter, section table, and trailer. Every
packed field width is a `LimitExceeded` refusal at build time rather than a truncation.
Bloom filter at 10 bits/entry and 7 hashes measures a 0.0080 false-positive rate; lookup
fan-out over 8 runs is 1 searched / 7 filtered on a hit in the oldest run and 0 / 8 on a
miss. These are the numbers §13 requires the result bundle to report.

Resident cost in the in-memory delta is **~93 bytes/entry**, materially above the packed
figure. At the default `max_active_index_entries = 4_000_000` that is ~370 MB per shard and
~1.5 GB across four shards — against 60 GiB of cgroup limit on both frozen profiles, so it
is comfortably inside §3's 80% ceiling and the default stands. The number worth watching is
seal frequency rather than bytes: at 75k commits/s over four shards each shard admits
~56k index entries/s, so a 4M-entry delta seals about every 71 seconds. Across a 900-second
P2 repetition that is ~13 runs per shard, under the `max_index_runs = 64` ceiling. Across a
two-hour P5 soak it would be ~100 runs, which exceeds it — and that is precisely the regime
where Phase 4 compaction exists to merge runs. The defaults are therefore correct for Phase
1 and P2, and P5 depends on compaction landing rather than on retuning them.

### 3.7 Durability ordering — normative

The append path, per group, on the owning shard thread only:

```text
 1  form group           (≤ max_group_transactions, ≤ max_group_bytes, ≤ max_idle_delay)
 2  recheck each signed retry deadline                     [oracle::deadline_expectation]
 3  mark every group operation Resolving in the status root (Release ordering)
 4  encode frames into iovecs at the current write cursor
 5  write_vectored_all  -> loop on short writes; verify final cursor == expected
 6  fdatasync(journal)   <-- THE fence. Exactly one per group.
 7  build the immutable shard subtree (index delta, snapshots, receipts, sequences)
 8  ArcSwap CAS the committed root; on contention, re-merge against the newer root
 9  remove the group's Resolving entries (Release, after step 8 is visible)
10  wake waiters with receipts
```

Normative rules attached to this sequence:

- **Steps 4–10 are the poison window.** Any error, cancellation, or panic anywhere in it
  poisons the shard: read-only, every affected operation `Resolving`, no further append,
  publication, or acknowledgment until close-and-reopen through recovery (§5.2).
- **`fdatasync` failure is terminal for the shard and is never retried.** On Linux an
  `fsync`/`fdatasync` error may be reported exactly once, after which the kernel has already
  dropped the dirty pages; a second call can return success while the data is permanently
  gone. Therefore a failed fence proves nothing about durability in either direction —
  which is precisely why contract review 2026-07-24-A moved `FenceFailed` to
  `EitherWhole`. Recovery must reopen the file with a fresh descriptor and re-read from the
  device before classifying.
- **A short write is not an error.** It leaves a durable prefix. `write_vectored_all` loops,
  and the group's outcome is decided per frame by completeness (3.3), not by the return
  value of any single call.
- **Only the shard owner names, adopts, renames, or unlinks anything under its shard.**
  Maintenance workers write uniquely named unreferenced artifacts and hand over descriptors
  (§4 resource invariants, §7 maintenance workers).

### 3.8 Recovery — normative

```text
 1  acquire LOCK; validate FORMAT and root_uuid
 2  read CURRENT -> manifests/<generation>.manifest; if CURRENT is missing/corrupt or
    any referenced file fails validation, fall back to the newest valid manifest
    generation whose referenced files all validate
 3  load the newest of >=2 validated checkpoints. Three outcomes, kept distinct:
      no checkpoint directory entries at all -> a fresh root; replay from the start
      at least one validates                 -> load the newest
      entries exist and all fail validation  -> explicit offline rebuild mode
 4  replay sealed segments above the checkpoint, then the active journal, in order
 5  scan the active journal forward from the checkpoint offset:
      at each offset, test completeness (3.3)
        complete   -> adopt, advance, continue
        incomplete -> STOP. This is the tail.
 6  everything at or after the stop offset is discarded, even if a later region
    contains a syntactically complete frame
 7  quarantine the discarded tail bytes to quarantine/<journal_id>-<offset>.tail
 8  seal the validated prefix into a segment and open a fresh journal; never rewrite
    a journal in place
 9  independently verify: shard_sequence contiguous, no duplicate; per repository
    repo_sequence contiguous, no duplicate, previous_event_digest chains
10  for each recovered operation whose first_receipt_visibility_micros was not in a
    durable checkpoint, set it to recovery publication time (extends, never shortens)
11  publish the recovered committed root and receipt table exactly once
12  readiness true only after replay and catalog/genesis validation complete
```

The three-way split in step 3 matters and the first draft collapsed it to two. A fresh root
has zero checkpoint generations and is perfectly healthy; treating that as "all generations
failed" would license a replay from sequence zero on a *corrupt* store, which is the exact
failure the rule exists to prevent. Emptiness and total corruption must be distinguishable
by the type recovery returns, not by a comment.

Two rules in there carry most of the risk and must be individually asserted, not asserted
in aggregate:

- **Step 6.** Page writeback may persist a later page before an earlier one. After a crash
  it is entirely possible to find frame *k* torn and frame *k+1* complete and
  checksum-valid. Adopting *k+1* would publish a hole and break `shard_sequence`
  contiguity, multi-ref atomicity, and the "wholly present or wholly absent" invariant.
  Recovery stops at the first incomplete frame, unconditionally.
- **Step 5 must handle both a zero/stale tail and `EIO`.** The frozen reference filesystem
  is btrfs with data checksums. Copy-on-write means an ordinary crash normally leaves the
  tail region reading as **zeros or stale preallocated content**, not as a torn block —
  CoW does not expose a half-updated extent. `EIO` is the *other* case: the device
  acknowledged a write it did not retain, which is live here because the frozen profile has
  `write_cache = enabled` and `power_loss_protection = false`. Recovery must therefore treat
  both a non-magic tail and an `EIO` in the tail region as "the tail ends here", never as a
  fatal store error; getting the latter wrong turns an ordinary crash into an unopenable
  store. Under `nodatacow` (9.2) the checksums are gone and a torn block reads back as
  garbage, which condition 5 of 3.3 catches. All three paths must be tested.

  The residual risk is real and must be named: treating `EIO` as end-of-tail will silently
  drop a frame that *was* fenced and that the device then lost. Recovery cannot distinguish
  that from an unfenced tail by inspection — nothing on the device says so. The detector is
  the external ACK journal reconciliation (A3 deliverable 5), which is run after every
  crash precisely because it is the only thing that can catch a device that lied about a
  flush. `acknowledged_loss` becoming non-zero there is a hardware finding, not a store bug,
  and it invalidates the run rather than being tolerated.

## 4. Wave A work packages

All three start together after D0. Each ends with its own tests green and its deliverables
reviewable in isolation.

### A1 — JournalWriter

Owns `format.rs` bodies, `journal.rs`, `segment.rs`.

Deliverables:

1. Frame, journal-header, segment-footer, and `CURRENT` codecs implementing 3.2–3.5, with
   checked readers in the Phase 0 style: bounded `with_capacity`, trailing-byte rejection,
   decode-side revalidation, no `serde`.
2. Group append with `write_vectored`, short-write looping, cursor verification, and
   exactly one `fdatasync` per group. Group formation bounded by transactions, bytes, and
   idle delay.
3. `shard_sequence` assignment and the crash-safe rotation/seal sequence of 3.4.
4. Every step in 3.7 instrumented with a `failpoints::hit` call, one per
   `AppendFailpoint` variant reachable at this layer (named in A3 deliverable 2).
5. **`drive.rs` bodies** — the `store-internals` journal-level API A3 drives in Wave A:
   open/create a shard journal, append a caller-supplied pre-encoded frame group, fence,
   seal, install a manifest, and reopen through `recovery.rs`. It exposes
   `DurabilityCounters` and the failpoint registry. It has no engine, status root,
   sequencer, or signer, and B1 does not build on it. This is A1's contract with A3 and is
   part of what the Wave A freeze gate freezes.
6. **Golden frame vectors** — `tests/fixtures/phase1-frames.json`, regenerated only by
   `cargo run -p levcs-store --example phase1_frame_golden`, covering: minimum frame,
   repository-create frame, multi-object frame, multi-ref Set+Delete frame, authority
   transition frame, staged-projection-install frame, one frame per `SourceKindV1`, and
   the maximum-`shard_sequence`/`repo_sequence` edge frames.
7. Negative decode coverage: every one of the eight completeness conditions in 3.3 violated
   independently — including a frame whose only defect is a non-zero `flags` and one whose
   only defect is a non-zero padding byte — plus wrong `journal_id`, wrong `root_uuid`,
   non-zero journal-header padding, `total_len` overflowing the file, `total_len` not
   8-aligned, truncation at every byte offset of a small frame, and single-bit mutation
   asserting the frame never validates.

Acceptance: goldens byte-stable across two regenerations; `fdatasync` counter equals group
count for a 10k-transaction run; a proptest showing encode/decode round-trips and that
truncation at any offset is rejected without panic.

### A2 — RecoveryIndex

Owns `index.rs`, `checkpoint.rs`, `recovery.rs`.

Deliverables:

1. `(namespace, ObjectId)` index: bounded in-memory delta, immutable mmapped sorted runs
   with the versioned Bloom filter, run count/fan-out ceilings, and a namespace catalog.
   **Namespace isolation is a property of the key, and there is a test that a byte-identical
   object inserted under namespace A is not found under namespace B** (Phase 1 exit).
2. Checkpoint construction, atomic installation, ≥2 validated generations, and explicit
   offline-rebuild mode when all validated generations fail.
3. Recovery implementing 3.8 exactly, including the two rules called out there.
4. Independent shard-sequence and repo-sequence/event-chain verification with distinct
   error variants — a shard gap and a repository gap must not be reported as the same fault.
5. Receipt-table reconstruction, including `first_receipt_visibility_micros` promotion
   (step 10) asserted against `oracle::recovered_receipt_visibility`.

Acceptance: for each of the following, a dedicated test, not a shared one — torn final
frame; complete frame after a torn frame (must be discarded); zeroed tail; stale
preallocated content in the tail; `EIO` on tail read; corrupt checkpoint (one generation,
then both); corrupt segment referenced by the active manifest; **corrupt `CURRENT` with a
valid predecessor manifest**; **valid `CURRENT` naming a missing manifest generation**;
**valid `CURRENT` naming a manifest that fails its own checksum**; wrong `journal_id`;
wrong `root_uuid`; shard-sequence duplicate; repo-sequence gap; `previous_event_digest`
mismatch.

The three manifest cases are distinct branches of recovery step 2 and may not be collapsed.
Corrupt-`CURRENT` exercises "the pointer does not validate"; the two naming cases exercise
"the pointer validates but its referent does not" — a failure the single-`CURRENT` layout
could not express and which the pointer design introduces. All three must fall back to the
newest valid manifest generation rather than to an error.

### A3 — StoreHarness

Owns the benchmark and crash harness, against the D0 public API.

Deliverables:

1. **Deterministic crash driver** — `store-crash-driver` child process; parent sets a
   failpoint by name, child runs a scripted workload **through A1's `drive.rs`** in Wave A
   and through `StoreEngine::submit` from Wave B onward, the failpoint fires
   (`Fail` | `Panic` | `HardExit` via `_exit(3)` so no destructor or buffer flush runs),
   parent reopens through production recovery and classifies the outcome. The two drive
   paths share one classifier; only the submission call differs.
2. **The crash matrix** — `tests/crash_matrix.rs` plus
   `tests/fixtures/phase1-failpoints.json`, one row per `AppendFailpoint`. Each row records
   the physical state class the failpoint produces and the recovery outcome observed, and
   the test asserts the observed outcome equals **both** the class-derived expectation
   **and** `oracle::append_publication_expectation(point).recovery_outcome`. Two independent
   derivations that must agree; no catch-all match arm anywhere in the file.

   | Failpoint | Physical state class | Required outcome |
   |---|---|---|
   | `BeforeAppend` | `NoBytes` | `AbsentRetriable` |
   | `AfterMarkedResolving` | `NoBytes` | `AbsentRetriable` |
   | `EvidenceHandoffFailure` | `NoBytes` | `AbsentRetriable` |
   | `DuringFrameWriteTorn` | `PartialFrame` | `AbsentRetriable` |
   | `AfterFrameWrite` | `WholeFrameUnfenced` | `EitherWhole` |
   | `BeforeFence` | `WholeFrameUnfenced` | `EitherWhole` |
   | `FenceFailed` | `WholeFrameUnfenced` | `EitherWhole` |
   | `FenceAmbiguous` | `WholeFrameUnfenced` | `EitherWhole` |
   | `WriterPanicBeforeFence` | `WholeFrameUnfenced` | `EitherWhole` |
   | `AfterSuccessfulFence` | `WholeFrameFenced` | `Committed` |
   | `DuringCommittedRootBuild` | `WholeFrameFenced` | `Committed` |
   | `AllocationFailureBeforePublication` | `WholeFrameFenced` | `Committed` |
   | `BeforeRootCas` | `WholeFrameFenced` | `Committed` |
   | `DuringRootCasRetry` | `WholeFrameFenced` | `Committed` |
   | `WriterPanicAfterFence` | `WholeFrameFenced` | `Committed` |
   | `AfterRootCasBeforeWaiterWake` | `WholeFrameFenced` + published | `Committed`, ack allowed |
   | `BeforeResponse` | `WholeFrameFenced` + published | `Committed`, ack allowed |

   Each fixture row carries an explicit `wave` field. The partition is given **by name**,
   never by count — the first draft said "the six publication-side rows" and the count was
   wrong, which is the same class of error as an unasserted field.

   *Wave A, drivable through `drive.rs` (nine):* `BeforeAppend`, `DuringFrameWriteTorn`,
   `AfterFrameWrite`, `BeforeFence`, `FenceFailed`, `FenceAmbiguous`,
   `WriterPanicBeforeFence`, `AfterSuccessfulFence`, `WriterPanicAfterFence`.

   *Wave B, requires B1 (eight):* `AfterMarkedResolving` (needs the status root),
   `EvidenceHandoffFailure` (needs the sequencer's signer handoff),
   `DuringCommittedRootBuild`, `AllocationFailureBeforePublication`, `BeforeRootCas`,
   `DuringRootCasRetry`, `AfterRootCasBeforeWaiterWake`, `BeforeResponse`.

   `WriterPanicAfterFence` is **ruled into Wave A**, read as "the writer thread panics once
   `fdatasync` has returned". The claim it certifies — a fenced frame survives a
   panic-unwind death of the writer — is a journal-layer claim, and `drive.rs` contains the
   panic site. Its whole differential against `AfterSuccessfulFence` is unwind versus clean
   error return, and unwind is where a `Drop` impl that truncates, rewinds the cursor, or
   flushes a buffer would corrupt the fenced prefix. That is a format-freeze concern, and
   the driver's `HardExit` path deliberately cannot catch it because `_exit(3)` runs no
   destructors. The halves this row cannot assert in Wave A — poison, `Resolving`, no-ack —
   are equally unassertable for all nine Wave A rows, so they do not distinguish it.

   Two conditions attach. **(a)** In Wave A the fixture records that only the
   physical-state-class and `recovery_outcome` halves are asserted; Wave B re-asserts every
   row's complete `FailpointExpectation` — `shard_poisoned`, `immediate_status`,
   `acknowledgment_allowed`, `later_append_allowed_before_recovery` — through `submit`.
   **(b)** The Wave B matrix must exercise the `Panic` action on the publication-side rows
   `DuringCommittedRootBuild`, `BeforeRootCas`, and `DuringRootCasRetry`, so the
   panic-in-publication coverage this assignment vacates is not lost. The failpoint enum
   names a *location*; the driver chooses the *action*, and the two axes are independent.

   Wave B rows are recorded as `pending-wave-b` with their reason, exactly as Phase 0's
   `not-exercised` adversarial rows are, and the fixture test asserts the pending set is
   empty at Phase 1 exit.
3. **Group-aware failpoint model.** `oracle::append_publication_expectation` is a
   single-transaction contract; a real group has up to 512 frames and a failpoint has a
   victim index. A3 adds `group_failpoint_expectation(point, victim_index, group_len)` in
   `levcs-store` and proves it degenerates to the oracle at `group_len == 1`. This layers on
   top of the frozen oracle; it does not change it (see 9.3).

   It must return a **contiguous adopted prefix**, not a per-frame classification. Each
   individual unfenced frame is independently either-whole via page writeback, so a
   per-frame answer would permit "frame 3 absent, frame 4 committed" — which recovery step 6
   forbids and which is exactly the bug the matrix exists to catch. The contract is:
   *there exists some* `p ≤ victim_index` *such that frames* `0..p` *are committed and
   frames* `p..group_len` *are absent*; frames at or after the victim are never committed.
   Stated that way the matrix can fail an implementation that adopts past a hole, which a
   per-frame formulation cannot.
4. **Fault injection through `sys.rs`** — short write, `ENOSPC`, `EIO` on `fdatasync`,
   `EIO` on `pread`, unexpected cursor. dm-flakey and power-cut belong to the reviewed
   root-only scripts of §10 and are Phase 4/5; Phase 1 gets the userspace layer so the
   matrix runs unprivileged in CI.
5. **External ACK reconciliation** — reuse `oracle::ExternalAckJournal`. Every
   acknowledged operation is durably journaled before it is counted; after each crash the
   harness proves zero acknowledged loss and zero torn transactions against the recovered
   store.
6. **Durable-ingest benchmark** — `benches/durable_ingest.rs` (criterion, over `drive.rs`,
   for the P1-micro diagnostic gate, runnable in Wave A) and `src/bin/store-bench.rs`
   (long-run, for P2: 5 min warmup + 15 min measured × 3, open-loop, coordinated-omission
   corrected, HDR histograms, emitting a `bench/result-schema.json`-conformant bundle with
   `gate = "storage_primitive"`). `store-bench` goes through the public `submit` and so
   produces a real bundle only from Wave B; in Wave A it must still compile, and its bundle
   emitter and free-space precheck (8.2) must be exercised against a short `drive.rs` run so
   the schema question in 9.1 is settled long before the gate depends on it. Real Ed25519
   evidence signing is on — §5.2 requires P2 to measure signing cost.
7. `scripts/verify-store-recovery.sh` — run the matrix, run *N* randomized `SIGKILL`
   cycles, reconcile against the ACK journal, print a machine-readable summary.

Acceptance splits by wave, because A3 cannot reach `submit` until B1 exists:

*Wave A* — the nine `drive.rs`-reachable matrix rows run green on their physical-class and
`recovery_outcome` halves, with the eight Wave B rows explicitly pending;
`verify-store-recovery.sh` completes 100
`SIGKILL` cycles through `drive.rs` with zero acknowledged loss; `durable_ingest` produces a
P1-micro number; `store-bench` compiles and emits a schema-valid skeleton bundle.

*Phase 1 exit* — zero pending rows, every row asserting its complete `FailpointExpectation`
through `submit`, and the `Panic` action exercised on the three publication-side rows named
above; `store-bench` produces a full P2 bundle over `submit`.

## 5. Wave A freeze gate and adversarial review charter

> **Wave A is frozen at commit `5ee9c6b78b6e5f77f988e99e477656cfdc7db352`** (2026-07-26).
> That commit is the frozen state: the `levcs-store` public API, the frame format and golden
> corpus, the durability ordering, the failpoint registry, and the crash/fault fixtures.
> Changing any of them now requires a contract review recorded in
> `doc/instance-throughput-rewrite-plan.md`, not an edit.
>
> Verified at that commit: `check-phase1.sh` `GATE_EXIT=0` across all four feature
> configurations, 124 test binaries, zero failures; `verify-store-recovery.sh --cycles 100`
> with `recovery_failures=0`, `acknowledged_loss=0`, `torn_transactions=0`,
> `repeated_adoptions=0`, `bundle=schema-valid`; `recovery_eio` 40/40 at four test threads;
> golden corpus byte-stable.
>
> Two carry-forwards are explicitly **not** covered by the freeze and are B-wave work: the
> crash-matrix extension and `GroupBuilder`'s production wiring, both below.
> `doc/swarm-fabric-roadmap-exploration.md` (commit `e6a058d`) is deliberately outside this
> freeze and remains non-binding.

Per §12 as amended: **Wave B starts only after Wave A's interfaces, golden frame vectors,
crash/fault fixtures, and durability ordering have passed review and are frozen.
Compilation alone is not the dependency gate.**

The gate is `scripts/check-phase1.sh` (lead-owned), modelled on `check-phase0.sh`:
`cargo fmt --all -- --check`, `cargo test --workspace`,
the whitespace check, three `levcs-store` feature configurations (default;
`failpoints,store-internals,store-privileged`; and `store-privileged` alone, so a leak into
the default build is not masked by the combined run), a check that no test or privileged
feature is enabled by default, a golden-drift check that `phase1-frames.json` matches a
fresh regeneration, and a check that the crash matrix carries no `pending-wave-b` rows once
`engine.rs` is implemented. It supersedes `check-phase0.sh` by running it, so the Phase 0
freeze stays enforced. The last two checks are inert until A1 and B1 land respectively, and
say so rather than passing silently.

A green gate is necessary and not sufficient. The review is adversarial and precedes the
freeze. The charter, derived from the plan's Phase 1 paragraph:

1. **Refute, do not confirm.** For each durability claim, construct the physical state that
   would falsify it. A review that reproduces the author's reasoning has not reviewed it.
2. **Attack the completeness definition (3.3) first.** Find a byte sequence that satisfies
   every completeness condition in 3.3 but is not a frame the writer produced, or a frame
   the writer produced that fails one condition. The charter says "every condition in 3.3",
   never a number: a stale count here would send the reviewer past exactly the conditions
   most recently added to close an attack, which is how this instruction fails silently.
3. **Attack step 6 of recovery.** Produce a crash image with a torn frame followed by a
   complete one and prove the store discards the later frame.
4. **Attack the fence.** `FenceFailed` and `FenceAmbiguous` must never resolve
   deterministically before recovery re-reads from the device with a fresh descriptor.
5. **Attack the seal/rotate/`CURRENT` sequence** at every ordering point: what is on disk
   if the process dies between each pair of adjacent steps in 3.4 and 3.5?
6. **Every frozen outcome individually asserted.** No catch-all match arm in any Phase 1
   expectation test. The reviewer greps for one and fails the gate if it exists — this is
   the specific defect that let contract review 2026-07-24-A's unsound classification ship.
7. **Counters, not claims.** "One fence per group" and "no per-object fsync" are checked
   against `DurabilityCounters`, not read out of the code.
8. **Assert against the path that runs, not the helper.** For every safety property, find
   the entry point production actually calls and check that *it* enforces the property. A
   helper that is correct, thoroughly tested, and never called is not a safeguard — it is a
   decoy that makes a review feel finished.

Item 8 is not hypothetical. It is what the Wave A review found (review record below), and
it is the same defect class as contract review 2026-07-24-A one level up: there, an
assertion covered every neighboring field except the wrong one; here, a test suite covered
every helper except the caller. Both produce a green gate over an unsound system, and
neither is visible to a reviewer who only reads the tests that exist.

The mechanical form of item 8: for each package, list the entry points its *consumers* call,
and confirm each safety property is asserted through one of those, not only through an
internal function. Where two packages meet, that list is the seam, and the seam is what
nobody owns by default.

9. **Ask every package what of its work is correct but uncalled.** Put the question to each
   author directly, as a required part of their report. The author of a helper is the only
   party who reliably knows whether anything calls it; a reviewer reading the tests sees
   coverage either way. In the Wave A review this single question turned two located
   symptoms into the whole class — it found that an entire module was uncalled by the path
   under test, which no amount of reading the passing tests would have surfaced.

Reviewer output is a written finding list. Freeze happens after findings are resolved, not
after they are filed.

### Wave A review record 2026-07-24-D

The adversarial review ran against a green gate — 1,478 passing test executions, all three
feature configurations, 100 `SIGKILL` cycles reporting zero acknowledged loss — and found
five defects, three of them blockers. That gap between "green" and "sound" is the record's
main point.

**P1 — recovery trusted segment footers without validating anything.**
`drive::reopen_through_recovery` pushed every sequence from a manifest-referenced segment's
footer offset table straight into the adopted set. It never validated frame bytes, never
checked `journal_id` or `root_uuid`, never decoded payloads, and never ran either sequence
verifier. `SegmentReader` validates the *footer*, not the frames it indexes. Reproduced: a
corrupted frame magic inside a referenced segment recovered "successfully" with
`acknowledged_loss=0`, and a journal moved from shard 1 into shard 0 was adopted whole.

**P1 — interrupted seals were double-adopted.** The same function adopted the manifest's
segment sequences and *then* unconditionally scanned the active journal, never calling
`recovery::classify_active_journal` or `recovery::complete_interrupted_seal`. A crash
between manifest install and active-name unlink produced `adopted_sequences=0,1,2,3,0,1,2,3`
reported as contiguous and untorn.

**P1 — `store-bench` emitted a schema-invalid bundle** and its test could not tell, because
the test matched JSON substrings rather than validating against the schema. The gate built
and ran the binary but never schema-validated either.

**P2 — a latency-gate failure was still unrepresentable.** Contract review 2026-07-24-B made
the one-minute-window rule conditional on `outcome` but left the per-gate latency ceilings
unconditional — the same defect one block over, missed the same way, for the third time in
this document's history. Now conditional.

**P2 — checkpoint writes bypassed the durability funnel**, so checkpoint bytes and short
writes were invisible to `DurabilityCounters` and no fault campaign could reach checkpoint
installation. The D0 guard missed it because it scanned for sync, rename, and unlink but not
for the writes being made durable. Extending the guard immediately surfaced a second bypass
nobody had reported, a `set_len` truncation in `journal.rs`.

**The cause, which matters more than the five items.** A2 built `classify_active_journal`,
`complete_interrupted_seal`, and both sequence verifiers, and tested them thoroughly. A1's
`drive.rs` reimplemented a simplified recovery and called none of them. Each package passed
its own tests; the seam between them was untested, and the seam is what the crash matrix,
the `SIGKILL` campaign, and the ACK reconciliation all actually drove.

No individual agent was negligent. The ownership matrix that keeps agents from colliding is
the same thing that leaves the join between them unowned — and the freeze gate cannot see
the difference between a property enforced and a property enforced somewhere. Charter item 8
above is the standing correction.

**Wider than the review found.** Asked directly whether anything else was correct-but-
uncalled, A2 disclosed that `drive.rs` contains no reference to `recovery::` at all: every
public entry point in `recovery.rs` is uncalled by the path the crash matrix drives, not
merely the two the review named. And `checkpoint::install` and `checkpoint::prune` have no
production caller anywhere in the crate, so **no crash image the matrix produces has a
checkpoint directory** — meaning recovery step 3's checkpoint selection, its one-generation-
corrupt fallback, and its all-corrupt offline-rebuild decision have never run against a real
crash image, only against directories a test assembled by hand.

Some of that is genuine sequencing: `engine.rs` is `NotImplemented` until B1, so there is no
production caller yet for anything. But `drive.rs` exists precisely so Wave A can be
exercised before B1, and a drive seam that skips half the production path defeats its own
purpose. The drive API therefore gains a checkpoint install, and the routing must consult a
checkpoint when one is present.

The disclosure is worth noting as a method result, not just a finding. The review located
two symptoms; asking each package "what of yours is correct but uncalled?" located the
class. That question belongs in the charter for every wave, because the agent that wrote a
helper is the only party who reliably knows whether anyone calls it.

**Closure (2026-07-26).** All five findings are closed and the wider class with them.

`drive::reopen_through_recovery` no longer contains a recovery decision of its own. It
delegates in order to `resolve_manifest`, `load_checkpoint`/`checkpoint_for_recovery`,
per-segment `validate_journal_binding` and `SegmentReader::read_frame`,
`classify_active_journal`, then *either* `complete_interrupted_seal` *or*
`recover_journal_tail` and never both, then both sequence verifiers and
`promote_receipt_visibility`. Every `recovery.rs` entry point is now called except two,
declared in a table with reasons rather than left silent. `ShardDrive::checkpoint()` gives
`checkpoint::install`/`prune` their first production caller, so checkpointed crash images
exist and recovery step 3 runs against images the drive produced rather than directories a
test assembled. `store-bench` now validates its emitted artifact against the frozen schema
with a five-mutation negative control, and the ACK reconciler distinguishes duplicates and
regressions from forward gaps instead of detecting only the last.

Two structural corrections outlast the findings:

- **`DriveRecovery` now carries the recovery report verbatim.** The seam previously kept
  recovery's *effects* and discarded its *decision*, so a test could ask what was adopted
  but not why — and a double adoption and a correct replay produce different dispositions
  and the same adoption set. That is precisely how the missing `classify_active_journal`
  call stayed invisible while its own unit tests passed. Tests now assert the disposition
  directly, including that an ordinary replay is classified `Replay` rather than merely
  producing a plausible adopted set, and that a shard with no active journal has *no*
  disposition — a third state, not a `Replay`. The suite is mutation-verified: forcing the
  classifier to `Replay` fails one test, forcing it to `AlreadySealed` fails eight. Before
  this change, forcing either failed none, because nothing asked.
- **The durability funnel guard now covers writes and truncations**, not just sync, rename,
  and unlink. It found one bypass the review had not reported.

**The crash matrix could not have caught finding 1, and still cannot.** Re-running it after
the fix produced identical results — 24/24 rows, 100/100 `SIGKILL` cycles, zero acknowledged
loss, nothing that previously passed now failing. That is not a vindication of the matrix and
was not reported as one: it has no failpoint that corrupts a frame inside a *sealed segment*
and none that moves a journal between shards of one root, so the workload never produced the
state finding 1 describes. Both properties are now covered by tests driving the production
entry point, so the property is enforced; what is missing is the randomized campaign's ability
to find that class unaided. Recorded as a B-wave matrix extension, owned by whoever next
touches the crash driver. A matrix that returns green on a defect it structurally cannot
express is the same trap as a helper nothing calls.

**Carry-forward, not closed.** `GroupBuilder` has no production caller: `drive.rs` takes
pre-formed groups, so deliverable 4-A1.2 — group formation bounded by transactions, bytes,
and idle delay — is asserted only in unit tests over a type nothing calls. This is
legitimately B1's `engine.rs` by sequencing, but it is the same class as the findings above,
and a deliverable exercised only in isolation is not met in the sense the freeze gate is
meant to assert. It is recorded as a Wave A carry-forward with B1 owning closure, not as
satisfied. `index::{catalog_mut, delta, delta_mut, run_count, set_lifecycle}` and
`format::{repo_id, resulting_state_digest}` are Wave-B-only for the same reason; sequencing,
recorded, no action.

A third finding surfaced during closure and is recorded because its failure mode is subtle:
`tests/recovery_eio.rs` was **intrinsically flaky** from intra-suite parallelism against the
process-global fault registry. Measured rather than estimated: **8 failures in 40 runs** of
that binary alone with the guard removed, 0 in 50 with it. A fault-injection suite that fails
intermittently is the worst case of all — it gets rerun until green, which is exactly when it
stops being able to tell you anything, because a real regression and the flake are
indistinguishable from outside.

The mechanism is worth stating because the obvious fix is the wrong one. The trigger was not
two tests arming at once; it was a test performing a **clean, unarmed** journal scan before
arming anything. That scan is itself a funnel read, so it consumed the fault another test had
armed. A lock held only across `arm` would not have helped — it must cover the whole test
body.

**`arm` therefore takes a token, and the compiler enforces it.** `drive::faults::serial()`
returns a `FaultSerial`; `faults::arm`/`disarm` and `points::arm`/`disarm` all require a
reference to it. One token covers both registries: they are separate globals, but both steer
the same drive operation, so a failpoint armed during another test's fault campaign
interferes exactly as badly as sharing one registry would.

A2 asked only for one shared definition of the lock, so it would have a home instead of
existing in four copies. That was correctly diagnosed but insufficient: a lock a test *may*
take is a lock a new test will not take. This exact file carried a header stating it was
deliberately the only test in it, and a second test had been added under that comment anyway.
A comment cannot fail a build; a parameter can. Acquiring the token also clears any residual
armed fault, since a test that panics cannot run its own cleanup and would otherwise deliver
its fault to whichever test ran next.

This is the same correction as charter item 8 in a different register. There, a property was
enforced somewhere and not on the path that runs. Here, an invariant was documented rather
than required. In both cases the gate reported green because nothing made the omission
expressible as a failure.

## 6. Wave B work packages

### B1 — NamespaceTxn

Owns `engine.rs`, `transaction.rs`, `snapshot.rs`, `staging.rs`.

1. `StoreEngine::open` with the four startup states, per-shard threads, and readiness.
2. Repository creation binding `repo_id` and genesis authority permanently in the catalog.
3. `ValidatedTransaction` and its sealed builder; privileged constructors for recovery
   (and, later, migration).
4. The shard sequencer: speculative state containing every earlier accepted transaction in
   the pending group; checks only mutable preconditions (operation ID/digest, repository
   lifecycle, snapshot/config/policy epoch, typed ref CAS, expected authority, precomputed
   force/ancestry facts); never re-parses, re-hashes, or re-verifies.
5. Independent `shard_sequence` and `repo_sequence` assignment, `previous_event_digest`
   chaining, `sequenced_at_micros`, event/state digest computation, and the
   `CommitEvidenceSigner` handoff **before** append, on its own bounded pool, returning in
   repository-sequence order.
6. `ArcSwap<CommittedRoot>` + bounded `ArcSwap<OperationStatusRoot>`, the CAS merge loop,
   and the linearizable A → status → B read of §5.1, asserted against
   `oracle::two_root_status_read`.
7. Receipts, idempotency, coalescing, and terminal retention: same-ID/same-digest attaches,
   same-ID/different-digest rejects, asserted against `oracle::coalescing_decision`;
   `receipt_visible_until` and `status_tombstone_until` from the frozen protocol functions.
8. `RepoSnapshot` sharing persistent substructures — a snapshot must not clone the index.
9. Bounded projection staging: begin, idempotent chunk-put, read-only resolver, seal to
   `StagedProjectionInstallV1`, abort, expiry, cleanup. Sealing cannot publish membership;
   only `submit` adopts. Validated against `validate_projection_stage_binding` and
   `validate_projection_stage_finalize`.

### B2 — StorageReviewer

Read-only durability, concurrency, and security review of the whole crate. Same charter as
section 5, extended to the publication half: the eight `pending-wave-b` failpoint rows
named in 4-A3, the `Panic`-action coverage required of the three publication-side rows, the
status-root/committed-root race, the CAS merge loop under concurrent shard publication,
staging-session isolation, and the `ValidatedTransaction` seal.

## 7. Phase 1 exit criteria and evidence

§12: *"Exit: P2 ≥75k, acknowledged crash recovery, namespace isolation, exact same-ref
winner, multi-ref atomicity, no per-object fsync."*

| Exit criterion | Evidence artifact | Owner |
|---|---|---|
| P2 ≥75k canonical commits/s, p99 ≤50 ms, 3 repetitions | `gate="storage_primitive"` bundle, schema-valid, ACK-reconciled | A3 |
| Acknowledged crash recovery | full 17-row crash matrix, zero pending; 100 `SIGKILL` cycles; `acknowledged_loss = 0`, `torn_transactions = 0` | A3 + A2 |
| Namespace isolation | identical bytes in A not readable through B; index key test | A2 |
| Exact same-ref winner | concurrent same-ref CAS: exactly one `Committed`, others typed conflict, no partial state | B1 |
| Multi-ref atomicity | multi-ref transaction crash-tested at every failpoint: all-old or all-new, never mixed | B1 + A3 |
| No per-object fsync | `DurabilityCounters.fdatasync == group_count` and `< transaction_count` over a ≥10k-transaction run | A1 |
| Recovery oracle passes | every assertion bound to `levcs-protocol::oracle`, no catch-all arms | A3 |

Also required before the phase closes, from §13's stop conditions: the result bundle must
report index bytes/object and checkpoint lookup fan-out, and the P2 runs must not have been
achieved with checkpointing disabled.

## 8. Capacity analysis for P2 on the frozen reference hardware

`bench/reference-hardware.toml` freezes both profiles as a Ryzen 7 9800X3D (8 physical
cores), 64 GiB, a **Samsung 990 PRO 1 TB** with `write_cache = enabled` and
`power_loss_protection = false`, on **btrfs** with `compress=zstd:3`, `data_profile=single`,
`metadata_profile=dup`, `barriers=enabled`. Three consequences bind Phase 1.

### 8.1 Write bandwidth and the fence rate

A canonical commit is a 1,024-byte blob + one-file tree + signed commit ≈ 1.5 KB raw; the
frame adds header, evidence, signed `CommittedTransactionV1`, and receipt fields for
roughly 2.5–3 KB per single-commit transaction. At 75k/s that is **~200 MB/s sustained
journal write**, comfortably inside a 990 PRO's direct-to-TLC rate.

The fence rate is set by the idle delay, not by the group ceiling. At the 512-transaction
ceiling 75k/s would be only ~147 groups/s, but that is the floor under maximal batching and
is not the operating point: with 4 shards and a 1 ms maximum idle delay, each shard closes a
group at least every millisecond, giving **~4,000 fences/s in groups of ~19**. That is the
number that must inform device-flush budgeting — 4k flushes/s at ~50–100 µs is ~20–40% of
one queue's service time on this device, comfortable but not free, and it is the parameter
P5 tuning will be tempted to relax. The 50 ms p99 budget remains dominated by the idle delay
plus queueing, not by the flush.

### 8.2 Capacity, not bandwidth, is the binding constraint

15 measured minutes at 75k/s writes **~170 GB of journal**, plus ~9.5 GB of index runs
(225k objects/s × 47 bytes/entry × 900 s). Three repetitions × four topologies would be
~2.2 TB on a 1 TB drive, and Phase 1 has no compaction to reclaim with.

Therefore the P2 procedure must be: **each measured repetition starts from a freshly
initialized store root**, and `store-bench` refuses to start unless free space is at least

```text
((warmup_seconds + measured_seconds) × target_rate × frame_bytes + index_run_estimate) × 1.25
```

The warmup writes too — 300 s of it, another ~56 GB — and the index runs, checkpoints, and
btrfs `metadata_profile = dup` overhead are all outside the journal figure. A precheck over
`measured_seconds` alone with a 25% margin covers only about 225 s of the 300 s warmup, so
it can pass and the run can still hit `ENOSPC` inside the measured window, which destroys
the repetition rather than failing it cleanly. Between repetitions the harness
must delete the root, let `discard=async` settle, and record the settle interval in the
bundle, so that repetition 3 does not run against a drive in a different garbage-collection
state than repetition 1. A3 owns this; it is not optional bookkeeping, it is the difference
between three comparable repetitions and three different experiments.

### 8.3 btrfs is copy-on-write, checksummed, and compressing

All three interact with a hand-rolled WAL:

- **CoW** means the preallocate-then-overwrite design of 3.2 does not actually overwrite in
  place; btrfs allocates new extents and updates metadata per write. The `fdatasync`-has-no-
  metadata-to-persist benefit is lost.
- **`compress=zstd:3`** will attempt to compress every journal write. Frame contents are
  BLAKE3 digests, Ed25519 signatures, and pseudo-random blob bytes — incompressible. That is
  pure CPU burned at 200 MB/s on an 8-core box that also needs ~1.4 cores for Ed25519
  evidence signing at 75k signatures/s.
- **Data checksums** turn a torn block into `EIO` on read rather than garbage, which is why
  3.8 step 5 must handle `EIO` as end-of-tail.

The standard mitigation is `chattr +C` (nodatacow) on `shards/*/active` and `segments`,
which restores in-place overwrite, disables compression, and disables data checksums —
making our own frame digest the sole integrity check, which it already is. See 9.2: this is
a decision, not a detail, and it changes which recovery behavior in 3.8 is live.

### 8.4 CPU budget

75k Ed25519 signatures/s at ~18 µs each is **~1.4 cores** of the 8 available, before
BLAKE3 (~0.2 core at 200 MB/s), index insertion at 225k entries/s, and four shard threads.
P2 has no validation pool, so this fits — but it means P2's headroom over 75k is not large,
and any per-transaction signature beyond the one `CommittedTransactionV1` signature would
consume it. The bundle must report signing cost separately (§5.2: "P2/P3 measure this
ordering, signing cost, and backpressure").

## 9. Decisions — all resolved 2026-07-24

Every item in this section was ruled on before D0. Each subsection states the question, the
recommendation as originally written, and the **ruling** with any conditions attached to it.
Nothing here is open; the subsections are retained because the reasoning is the record.

9.1 and 9.2 together constitute **contract review 2026-07-24-B**, amending two frozen
Phase 0 benchmark artifacts (`bench/result-schema.json` and `bench/reference-hardware.toml`).
Per the Phase 0 freeze rules it must be recorded in `doc/instance-throughput-rewrite-plan.md`
the way contract review 2026-07-24-A was, before A3's bundle emitter is written.

### 9.1 `result-schema.json` cannot validate a storage-primitive bundle — contract review 2026-07-24-B

`bench/result-schema.json` is frozen and its `gate` enum already includes
`storage_primitive`. But the schema requires, unconditionally for every gate:

- `workload.validation_flags.*` all `const: true`, including `request_signature`, `replay`,
  `pack_hash_and_framing`, `complete_graph`, `authority_and_role`, `instance_policy`, and
  `repository_policy`.
- `deployment.proxy`, `deployment.tls`, `deployment.systemd`, `deployment.cgroup` with
  `minLength: 1`.

A P2 run is, by §3's own definition, against the "Production `levcs-store` API" — a layer
that §5.1 explicitly forbids from making identity-role, policy, or federation decisions,
and that runs in-process with no proxy or TLS. Reporting those flags as `true` would be
false; reporting them as `false` fails the frozen schema. The `deployment` strings can be
answered honestly (`"none (in-process P2)"` satisfies `minLength`), but `validation_flags`
cannot.

Recommended resolution, as **contract review 2026-07-24-B**: make `validation_flags`
conditional on `gate`, **per flag rather than as a block**, and add a required
`promotable: false`. A blanket `const: false` for `gate = "storage_primitive"` would be
wrong in the other direction: it would force `durability_fence_before_response: false` on
the one bundle whose entire purpose is to certify that the fence precedes acknowledgment,
and would deny `typed_ref_cas`, which the shard sequencer genuinely enforces.

For `gate = "storage_primitive"`:

| Flag | Required value | Why |
|---|---|---|
| `durability_fence_before_response` | `true` | The store *is* the fence. This is the claim under test. |
| `typed_ref_cas` | `true` | The sequencer performs the typed CAS against speculative state. |
| `request_signature` | `false` | No envelope at this layer. |
| `replay` | `false` | Replay guard is Phase 2 admission. |
| `pack_hash_and_framing` | `false` | No Pack; objects arrive already parsed. |
| `outer_embedded_type_match` | `false` | Parse-once overlay is Phase 2. |
| `complete_graph` | `false` | §5.1 forbids the store from traversing the graph. |
| `authority_and_role` | `false` | §5.1 forbids identity-role decisions. |
| `instance_policy` | `false` | Policy evaluation is Phase 2. |
| `repository_policy` | `false` | Policy evaluation is Phase 2. |
| `fast_forward` | `false` | The store consumes precomputed ancestry facts (§7 stage 9); it does not derive them. |

This encodes §3's rule — "A storage primitive result can never be promoted to an instance
throughput claim" — in the schema instead of in prose, and does so more precisely than a
blanket denial: the bundle states exactly which checks the measured system performed. Note
that `$defs.validation_flags` and the top-level object both set `additionalProperties:
false`, so `promotable` must be added explicitly wherever it lands, not merely permitted.

**Ruling: approved as written**, including `fast_forward` in the false column — a
validation flag must state what the measured system performed, and the sequencer consumes
ancestry facts rather than deriving them. Two implementation constraints so that
2026-07-24-B does not weaken what it amends:

**(a) Relaxing is not un-pinning.** Making the nine flags conditional means removing their
`const: true` from `$defs.validation_flags`. Every other gate's `if`/`then` branch —
`in_process_protocol`, `deployed_30k`, `deployed_60k`, and the remaining `gate` values —
must then re-pin all eleven flags to `true` explicitly. Otherwise the amendment silently
un-pins validation for the P3/P4/P5 bundles, which is a strictly worse defect than the one
it fixes: it would let a deployed-node result declare `complete_graph: false` and still
validate. A schema test must assert that for every `gate` value other than
`storage_primitive`, a bundle with any flag false fails validation.

**(b) `promotable` is required at top level for every gate**, `const: false` under
`storage_primitive` and `const: true` otherwise — not a field that only storage-primitive
bundles carry. An evaluator's refusal to promote then becomes a mechanical schema check
rather than a lookup in prose, which is the entire point of moving the rule out of §3's
text.

### 9.2 btrfs `nodatacow` for journal and segment directories

Decide before A1 and A2 write recovery, because it determines whether a torn tail read
returns `EIO` (CoW, checksums on) or garbage (nodatacow, checksums off), and 3.8 step 5
must handle whichever is live. Recommendation: **run nodatacow, and still handle `EIO`**.
Nodatacow makes preallocate-and-overwrite real, removes futile zstd work on incompressible
data, and our frame digest already provides end-to-end integrity that is strictly stronger
than a per-block csum for our purposes. Handling `EIO` anyway costs nothing and keeps the
store correct on a default-mounted root, and it remains necessary under either choice
because `power_loss_protection = false` means the device can lose acknowledged writes
regardless of filesystem.

The same ruling must answer a second question the first draft left open: **does `chattr +C`
on `shards/*/active` and `shards/*/segments` amend the frozen hardware profile, or is it
per-bundle metadata?** `reference-hardware.toml` freezes `mount_options` including
`compress=zstd:3`, and per-directory `nodatacow` overrides compression and checksums for
exactly the files that carry the throughput. Recommendation: treat it as an amendment to
`bench/reference-hardware.toml` — add a `[profile.filesystem].store_directory_attributes`
field naming the attribute and the directories it applies to — folded into contract review
2026-07-24-B alongside 9.1, since both are benchmark-contract changes and both must land
before A3's emitter. Per-bundle recording is then additionally required but is not
sufficient: a profile that silently permits two different on-disk configurations is not a
frozen profile.

**Ruling: approved, including the profile amendment.** Run `nodatacow`, handle `EIO` under
either configuration, and add `[profile.filesystem].store_directory_attributes` to
`bench/reference-hardware.toml` as part of 2026-07-24-B, recorded in the plan.

One condition: **`store-bench` must verify the effective attributes at startup and refuse
to run on mismatch**, not merely record them. It reads the inode flags back for each
configured store directory and compares them against the profile. Recording alone is
insufficient for the same reason the profile amendment is necessary — a run on a silently
copy-on-write-mounted root would otherwise emit a bundle claiming `nodatacow`, and the
resulting number would be incomparable to every other P2 result while looking identical.
The check belongs with the free-space precheck of 8.2 in the same refuse-to-start path.

### 9.3 Group-aware failpoint expectations

Confirm the reading in A3 deliverable 3: the frozen single-transaction oracle stays
unchanged and `levcs-store` layers `group_failpoint_expectation` on top, proving degeneracy
at `group_len == 1`. The alternative — extending `oracle.rs` — would require a Phase 0
contract review and regolden, for a concept that is a property of the storage engine rather
than of the protocol. Recommendation: layer, do not extend.

Confirm also that the layered function returns the **contiguous-prefix** contract of A3
deliverable 3 rather than a per-frame classification. This is the substance of the decision,
not a detail of it: a per-frame formulation is satisfied by an implementation that adopts a
valid frame sitting after a hole, which is the single most consequential recovery bug this
phase can ship.

**Ruling: approved.** Layer, do not extend the frozen oracle. The contiguous-prefix contract
— ∃ *p* ≤ `victim_index` splitting committed from absent, with nothing at or after the
victim ever committed — is the operative content of the function.

One condition: the degeneracy proof at `group_len == 1` must hold for **every physical state
class** — `NoBytes`, `PartialFrame`, `WholeFrameUnfenced`, and `WholeFrameFenced` — not only
for the torn one. A degeneracy proof covering a single class does not establish that the
layered function generalizes the oracle; it establishes that the two agree on one input.

### 9.4 `payload_digest` redundancy

3.3 carries both `payload_digest` (over the payload) and `frame_digest` (over everything).
The cost is 32 bytes per frame and a **second full pass over the payload** — since the
payload is nearly the whole frame, this roughly doubles store-side BLAKE3 work, from about
0.2 to about 0.4 of a core at 200 MB/s. That is still cheap on an 8-core box, and it buys
the ability to validate a payload read by `pread` from the index without re-reading the
trailer. Recommendation: keep it; revisit at Phase 5 if profiles say otherwise. Confirm in
D0 because it is a frozen-byte decision. (The first draft priced this as "a few percent of
BLAKE3 time", which described the 32 extra bytes hashed rather than the extra pass.)

**Ruling: approved.** Keep `payload_digest` at the corrected ~0.4-core price; freeze the
field in D0.

### 9.5 P2 measurement without an instance

`store-bench` must generate the canonical workload's object graph itself (deterministic
1,024-byte blobs from the frozen seed, real Ed25519 commits, real authority) and construct
`ValidatedTransaction` through the privileged constructor. Confirm this is acceptable and
is not "a benchmark-only shortcut" in the Phase 0 exit sense: it is not, because the store
is genuinely the system under test and the bundle declares `validation_flags` false and
`promotable: false` under 9.1. But it should be stated explicitly rather than assumed.

**Ruling: approved**, with one tightening that makes the claim checkable instead of
declared: the bundle's `workload.seed` and `workload.generator` must equal the frozen values
in `bench/workloads/small-commit.toml` — `seed = 126394451485337` and
`generator = "blake3-xof(seed || repo_ordinal_le || ref_ordinal_le || commit_ordinal_le)"`.
The generator is already pinned in the frozen workload, so an evaluator can recompute every
1,024-byte blob from the bundle alone and verify it against the recovered store. That turns
"the harness generated the canonical workload" from an assertion into a reproduction, which
is what separates this from the benchmark-only shortcuts the Phase 0 exit criteria forbid.
`workload.generator` is not currently a schema field; adding it is part of 2026-07-24-B.

### 9.6 Deferred to Phase 2: no public canonical codec for typed ref CAS

`TypedRefCas`, `RefTarget`, and `RefMutation` are frozen Phase 0 types with no public
`CanonicalCodec` implementation, so `levcs-store` had to define its own physical encoding
for the "complete typed ref CAS set" that scope 3.3 requires in every frame. That is a
drift surface: two encodings of the same logical content, only one of which is frozen.

It is not Phase 1's to close. `v2.rs` is a frozen artifact and exposing public codecs for
those types belongs to Phase 2 **ProtocolV2**, which owns protocol codecs. Phase 1 keeps
its physical encoding and delegates ref-name validation to `levcs_core::refs::
validate_ref_name` — the same function the protocol uses — so the two cannot disagree about
what a legal ref name is. When ProtocolV2 exposes the codec, the store's encoding must be
validated against it. Recorded here so the obligation is not lost between phases.

## 10. Risks

- **Custom journal correctness** (§13). If the crash matrix cannot be made deterministic,
  or recovery requires guessing, stop performance work and fix the format. The gate for
  this is section 5's charter, not the benchmark.
- **Index memory at sustained rates** (§13). 8.2's arithmetic must be validated, not
  assumed; if entries cost materially more than 47 bytes, or run fan-out grows unbounded,
  redesign before tuning.
- **Wave A/Wave B seam.** Eight failpoints, named in 4-A3, are unreachable until B1 exists,
  and all nine Wave A rows can assert only two of the five `FailpointExpectation` fields
  until then. The risk is that either set is quietly forgotten, and the first draft of this
  document demonstrated the failure mode by miscounting them. Mitigation: each Wave B row is
  a named `pending-wave-b` entry carrying a `wave` field, and the Wave A rows record which
  halves they assert; the fixture test requires both the pending set to be empty and every
  row to assert its complete expectation at Phase 1 exit — the same mechanism Phase 0 used
  for `not-exercised` adversarial rows. No count anywhere substitutes for the names.
- **`drive.rs` divergence.** A test-only seam that appends frames without the sequencer can
  drift from the real append path, at which point the Wave A matrix certifies something the
  production writer does not do. Mitigation: `drive.rs` must call the same `journal.rs`
  group-append and fence functions `engine.rs` calls, adding only frame construction; a
  Wave B test asserts a group submitted through `submit` and the same group driven through
  `drive.rs` produce byte-identical journal contents.
- **The 8-core budget.** 8.4 shows P2 headroom over 75k is modest. If P2 lands close to the
  bar, resist tuning the fence or the group ceiling to reach it; §13 forbids raising tuning
  parameters to hide overload, and P3 will only add load to the same cores.
- **Format churn after freeze.** Every post-freeze frame change invalidates the goldens and
  the crash fixtures. The mitigation is the completeness of section 3 before Wave A starts,
  which is what section 9 is for.

## 11. Sequencing

```text
D0  lead skeleton, frozen API, sys/failpoint shims, deps, decisions 9.1-9.5
     |
     +-- A1 JournalWriter  ---+
     +-- A2 RecoveryIndex  ---+--> Wave A freeze gate: check-phase1.sh + adversarial review
     +-- A3 StoreHarness   ---+          |
                                         v
                              B1 NamespaceTxn  ||  B2 StorageReviewer
                                         |
                                         v
                              Phase 1 exit: P2 x3, full crash matrix, section 7 table
```

Section 9 is resolved, so Wave A is unblocked once D0 lands. One item remains sequenced
ahead of A3: **contract review 2026-07-24-B** — the `result-schema.json` per-flag
conditional with its re-pin requirement and the top-level `promotable`, the added
`workload.generator` field, and `reference-hardware.toml`'s `store_directory_attributes` —
must be applied and recorded in `doc/instance-throughput-rewrite-plan.md` the way
2026-07-24-A was before A3 writes the bundle emitter. It is not a Wave A deliverable; it is
lead work that runs alongside D0.

Within Wave A the three packages are not equally unblocked. A1's `format.rs` and `drive.rs`
bodies gate A3's crash driver and benchmark, and A1's frame codec gates A2's recovery
scanner. A1 should therefore land `format.rs` and `drive.rs` first and in that order, before
`journal.rs` internals, so A2 and A3 are not idle. A3's Wave A output is a working matrix
over eight or nine rows and a P1-micro number, not a P2 result; the P2 bundle is a Phase 1
exit artifact that depends on B1.
