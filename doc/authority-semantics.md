# Authority semantics: history, replication, publication

**Status: ratified by the owner on 2026-10-04.** Ratified: the terms;
rules H, R and P; decisions D1, D2, D4 and D5 as written. D3 and D6 are
deferred. D6 needs an independent trust decision, so its recommendation
below is a proposal only. Nothing here is implemented. This note is the
specification that `verify`, replication and admission will enforce (audit
2026-10-03, revised: step 7; findings C1, C2).

**Relation to the frozen v2 contract.** For publication, the push
contract in `doc/instance-throughput-rewrite-plan.md` §6.1 governs:
newly exposed commits cite `expected_authority`, and a successor arrives
through one boundary commit, with commits citing it in a later
transaction. This note adopts that contract unchanged, and applies the
same rule to the v1 instance's admission step until the cutover.
Nothing in the plan is superseded. Rules H and R below cover what the
contract does not: historical verification, and receiving history that
was already published.

## Terms

An **authority** is a signed membership object: `repo_id`,
`previous_authority`, `version`, members with roles, and policy.

**Genesis** is the authority with a zero `previous_authority` and
`version = 1`. The `repo_id` is the BLAKE3 of the genesis body with
`repo_id` zeroed (`verify_genesis`), so the `repo_id` pins exactly one
genesis.

A **successor** of authority `A` names `A` as previous, has version
`A.version + 1`, and is signed by an `Owner` of `A` (`verify_successor`).

`B` **descends from** `A` when following `previous_authority` from `B`
reaches `A`. Two authorities are **comparable** when one descends from
the other.

**`A(C)`** is the authority commit `C` cites.

**`E(C)`** is the authority in effect after `C`:
- If `C` modifies authority, `E(C)` is the successor `C` installs at
  `.levcs/authority`. That successor must be a direct successor of
  `A(C)`.
- Otherwise, `E(C) = A(C)`.

Fork commits keep their implemented rule and the v2 `ForkProofV2` path.

A repository's **authoritative state** depends on where it is published:
- **With an authoritative instance:** the state is that instance's accepted
  refs. A local clone's refs are a workspace.
- **With no instance**, as with the vaults: the state is the repository's
  own branch, release and authority refs. It never includes `refs/remote/…`.

**`S0`** is the authoritative state before a transaction, with
`A0 = refs/authority/current`.

**`R0`** contains the commits admitted to the destination's authoritative
state before the transaction. Object presence, remote refs and workspace
refs do not establish admission. Authenticated v2 bootstrap and mirror
transitions may establish accepted state through their specified
evidence checks; unsigned v1 remote refs cannot.

A commit is **newly exposed** by a transaction if the transaction makes
the authoritative state reach it and `R0` does not contain it.

Why `A(C)` and `E(C)` differ: an authority-changing commit cites the old
authority and installs the new one only in its tree
(`identity_cmds.rs:253-262`). A rule comparing only cited authorities
lets a revoked author's commit sit directly on the revoking commit, since
both cite the old authority.

## Rule H: historical validity

Rule H is intrinsic to the history: it depends only on the objects, never
on a destination ref or on the receiver's state. A commit `C` with
parents `P1 … Pk` is historically valid if and only if all of these
hold:

1. **Signature and intrinsic role.** The signature is valid. The signer
   is a member of `A(C)`, holding `Owner` if `C` modifies authority and
   `Contributor` otherwise.

   There is no protected-ref requirement here. A commit does not record
   the ref it was made for, and requiring `Maintainer` throughout a
   protected branch's ancestry would reject legitimate Contributor
   commits merged in from feature branches. Protected refs are P.4.
2. **Pinned chain.** `A(C)`'s chain ends at the genesis pinned by
   `repo_id`.
3. **Monotone in every parent.** For every parent `Pi`, `A(C)` equals or
   descends from `E(Pi)`.
4. **Root commits.** A commit with no parents cites the pinned genesis.
5. **Authority changes.** If `C` modifies authority, `E(C)` is a valid
   direct successor of `A(C)` with at least one `Owner` (D4).

**Releases.** A release is valid if its declarer holds `Maintainer` or
above in `A(release)`, and `A(release)` equals or descends from
`E(predecessor)` (D5).

H.3 is the revocation rule. Every descendant of a commit that installs
`v2` cites `v2` or later. It is also the merge rule:
- When the parents' effective authorities are comparable, a merge cites
  the newer one or a successor of it.
- When they are incomparable, no authority satisfies H.3, and the
  situation is a hard conflict. `merge` refuses it and `verify` rejects a
  commit that claims to resolve it. Version numbers cannot settle it.
  Reconciliation is D3.

**`verify` outcomes.** `verify` reports one of three, and keeps them
distinct:
- **valid**;
- **invalid**: a bad signature, an unauthorized role, or a broken or
  foreign chain;
- **valid on a conflicting lineage**: the commit is historically valid,
  but cites an authority that is incomparable with this replica's
  canonical lineage (D2).

## Rule R: replication

Replication is receiving history that was already published elsewhere:
`pull`, `mirror`, the read side of `fork`, and the receiving side of
`dial`.

1. **Every received commit and release passes Rule H** against the
   genesis pinned by the expected `repo_id`. If a chain ends at a
   different genesis, the transfer is refused: that is a different
   repository.
2. **No membership is required of the receiver.** The receiver needs only
   the source's read permission: `public_read`, or a role of at least
   `Reader` there. A reader of a public repository is not a contributor.
3. **Revoked authors are no obstacle.** History containing commits by
   since-revoked authors is accepted when it passes H. A fresh replica has
   to be able to reproduce the history as it was published.
4. **Received refs are records of the source's state.** Replication
   admits nothing to the destination's authoritative state. Promoting
   received history into authoritative refs is a publication, and must
   pass Rule P like any other. Replication therefore never makes a commit
   eligible for publication indirectly. A historically valid commit citing
   a stale authority can be received under `refs/remote/…`, but it is
   still newly exposed when promoted, so it still needs adoption.

**Evidence of prior publication.** A commit counts as previously
published when a ref of the authoritative instance's accepted state
reached it. A replica can know this only from evidence that instance
signs:
- **v2:** the source-signed, hash-chained committed-transaction feed and
  receipts (plan §5.5, §6.2), under an instance key the replica has
  pinned, are that evidence.
- **v1:** there is no such evidence. A v1 replica's view of what was
  published is the source's unsigned word, and it should be recorded as
  such: the `refs/remote/…` namespace, not branch refs.

## Rule P: publication

Publication is changing a repository's authoritative state. That means a
push to its authoritative instance, or, for a repository with no instance,
any local command that moves its branch, release or authority refs,
including the promotion of received history. It is evaluated against the
single pre-transaction state `S0`.
1. **The transaction's signer** holds at least `Contributor` in `A0`.
   An authority the request names is not used; that substitution is C1.
2. **Newly exposed commits** must all pass Rule H.
   - Each must cite, and be authorized by, `A0` exactly. This is the v2
     contract.
   - The one exception is a single authority-transition boundary commit.
     It cites `A0`, installs a direct successor `A1`, and is authored by
     an `Owner` of `A0`.
   - No newly exposed commit may cite `A1`. Commits that do are accepted
     in a later transaction, whose `A0` is `A1`.
   - Releases follow the same rule.
3. **`current` moves only with that boundary,** by compare-and-swap from
   `A0` to `A1`. Any other change to `refs/authority/*` is refused; that
   was the rollback and genesis overwrite in C1.
4. **Ref updates.** These rules are separate from H:
   - Updating a protected ref requires the transaction's signer to hold
     `Maintainer` in `A0`.
   - A non-fast-forward update also requires `Maintainer` in `A0`, with
     ancestry walked over verified objects only.
5. **Nothing self-authorizes.**
   - `A0` and `R0` are fixed before the transaction, so incoming refs
     cannot grandfather their own commits.
   - An incoming membership change cannot authorize its own submission:
     everything in the transaction is checked against `A0`, never `A1`.

The local `commit` command already cites the current authority. Its
local checks are P.1 and P.2 applied to a single commit. In a clone of an
instance-hosted repository, local refs are a workspace: P is applied by
the instance when the work is pushed, against the instance's `R0`.

## What these rules do not establish

**Time.** Timestamps are self-asserted.
- **What a log can show:** a trusted log or witness can establish that
  signed bytes existed before a revocation, if they were logged before it.
- **What it cannot:** bytes first observed after a revocation are not
  thereby shown to have been signed after it.
- **The consequence:** without evidence of earlier existence, work citing
  an older authority is of unknown timing. Rule P therefore requires it to
  be adopted before it is published (D1).

**Global agreement.** Rule P makes `current` linear within one replica.
Two disconnected replicas can still each accept a different successor.
The rules detect that disagreement when the replicas meet (D2); they do
not prevent it. Preventing it needs a witness both replicas consult.

**Content.** These rules say who may write history, not whether what they
wrote is correct.

## Decisions

**D1. Work made under an older authority.**
- **Why it arises:** under P.2, no newly exposed commit may cite anything
  but `A0`. A contributor's offline work made under `v1`, or work by a
  member since removed, therefore cannot be published as it stands.
- **Recommendation: adoption.** A current member publishes it as their own
  commit, citing `A0`. That commit records three things:
  - the original commit's id;
  - its author's key;
  - the hash of the original signed object, which stays retrievable
    outside the published ancestry.
- **What adoption claims:** that the adopter took the work in, not that
  they wrote it. Original authorship stays checkable against the original
  signature.
- **What remains open:** the record's format is undefined. It belongs with
  the artifact envelope contract that `doc/swarm-fabric-roadmap-exploration.md`
  §2.4 proposes, since an adoption is a statement about a subject, made by
  someone other than its author.
- **Without an adoption record:** such work is refused.

**D2. Authority equivocation.**
- **Recommendation:** within a replica, the lineage ending at that
  replica's accepted `current` is canonical. P.3 keeps it linear there.
- **When replicas meet:** an incomparable lineage is a detected
  disagreement. `verify` reports commits on it as valid on a conflicting
  lineage, not as invalid signatures.
- **What this does not do:** prevent equivocation globally. See "Global
  agreement" above.

**D3. Reconciling incomparable authority histories.** Deferred. Merges
across them are a hard conflict until an explicit reconciliation object
exists.

**D4. Ownerless successors.** Adopt rejection, per H.5, in verification
and in `authority remove` and `promote`.

**D5. Release declarers.** Adopt: `Maintainer` or above in `A(release)`.
Today any member, a Reader included, passes (finding H13).

**D6. Bootstrapping an authoritative replica under v1.** Deferred: it
needs an independent trust decision. The recommendation below is a
proposal, not ratified policy.
- **The case:** a repository with no instance copied whole to a second
  machine, for example by `dial`. The copy becomes authoritative for itself,
  but it starts with an empty `R0` and no `A0`.
- **The gap:** under P, every received commit is newly exposed. Under v1,
  nothing establishes that the history was published at the source. Any
  history spanning a membership change therefore cannot be promoted.
  `~/apocrypha`'s does: it went from v1 to v2 when `agent` was added.
- **Recommendation:** an `Owner` of the received current authority accepts
  the bootstrap explicitly, with one signed statement naming the received
  refs and their closure. Admission then rests on that owner's word, which
  is the only trust a v1 transfer can offer. The statement is another
  artifact-envelope object, like D1's adoption record.
- **Until that exists:** a v1 bootstrap leaves the received history in
  `refs/remote/…`. The replica can read it but cannot publish from it.
- **Under v2:** the authenticated bootstrap and its signed evidence take
  this role, and D6 does not arise.

## Implementation notes

These are not part of the ratification.
- **Computing `E`.** `E(C)` needs one tree lookup per authority-changing
  commit; memoize `E` per commit during a closure walk.
- **"Descends from."** Walk `previous_authority` back to genesis, cached
  per authority id.
- **Pinning.** `verify` takes `refs/authority/genesis`, checked against
  `repo_id`. Admission and replication take the genesis derived from the
  validated 64-hex `repo_id` they were asked for.
- **Tests:**
  - **Rule H (verify):**
    - a revoked author's commit on the revoking commit (invalid);
    - a merge of comparable authorities (must cite the newer one);
    - a merge of incomparable authorities (invalid);
    - a Contributor commit in a protected branch's ancestry (valid);
    - a Reader-signed release (invalid);
    - an ownerless successor (invalid);
    - two successors when replicas meet (valid on a conflicting lineage).
  - **Rule R (replication):**
    - a fresh replica receiving history with a since-revoked author
      (accepted);
    - a reader replicating a public repository (accepted).
  - **Rule P (publication):**
    - an unpublished `v1` commit by a still-current member after `v2`
      (refused unless adopted);
    - an incoming ref that would grandfather its own commits (refused);
    - an incoming membership change in the same transaction as commits
      citing it (refused);
    - a rollback of `current` (refused);
    - a Contributor updating a protected ref (refused);
    - a stale-authority commit replicated under `refs/remote/…`, then
      promoted: replication succeeds, but promotion is refused unless the
      commit is adopted.
