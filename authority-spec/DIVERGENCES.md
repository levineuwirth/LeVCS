# Where the implementation and the ratified text part ways

This records what writing the executable specification turned up. Nothing
here has been decided: each divergence is either an amendment to
`doc/authority-semantics.md` or a change to the Rust, and that is the owner's
call.

There are six kinds of entry:

- **Divergences:** the text says one thing and the Rust enforces more. Each
  is a switch in `LeVCS.Authority.Reading` and has a witness in `corpus/`.
- **Readings:** the text leaves something implicit and the model had to
  choose.
- **Untested contract requirements:** the text does say, and nothing here
  tests it.
- **Gaps:** the text is silent, so the generators never produce the case and
  nothing here tests it.
- **Consequences:** things the rules imply that the text does not say.
- **Defects found on the way:** faults in the Rust that are no part of the
  authority rules.

## Divergences

In every one the Rust is stricter than the text, never looser. Three
properties named "the implemented reading only ever refuses more" check
that:

- **For history:** every clause an object breaks under the literal text, it
  breaks under the implemented reading.
- **For publication:** every transaction, put to the same pre-state under
  both readings, breaks at least as much under the implemented reading, and
  where both admit it they admit the same thing.
- **For replication:** every transfer the implemented reading records, the
  literal text records, as the same objects.

Each was confirmed by holding the Rust to every divergence but that one
(`LEVCS_SPEC_READING=without:<letter>`): the run fails and shrinks to the
witness's shape. With all eight switches applied, the Rust and the model
agree.

### (a) A successor must be signed by the author of the commit that installs it

- **Text:** a successor "is signed by an `Owner` of `A`" (Terms), and H.5
  asks for "a valid direct successor of `A(C)` with at least one `Owner`".
- **Rust:** the boundary commit's author must also be among the successor's
  signers. `verify_successor` (`verify.rs:365`), called from `check_commit`
  (`history.rs:417`).
- **Effect:** with two Owners, one cannot sign a successor that the other
  commits.
- **Note:** the Terms section names `verify_successor` as the definition, so
  the text may be meant to include this.
- **With (b):** the author's signature must be one that verifies. An entry
  bearing the author's key that does not verify is no signature. In the Rust
  the question never arises, because (b) rejects the successor first; the
  model states it so that (a) means the same with (b) switched off.
- **Witnesses:** `div-a-successor-not-signed-by-the-boundary-author`;
  `div-a-publishing-a-successor-its-author-did-not-sign`, the same boundary
  put to `admit`; `div-ab-boundary-author-signature-does-not-verify`, which
  has an answer written out for `without:a` and for `without:b`.

### (b) Every signature on an authority must verify

- **Text:** one signature by an Owner of the predecessor.
- **Rust:** an authority is rejected if any signature on it fails, on every
  authority in a chain, the genesis included (`history.rs:219`).
- **Effect:** an authority carrying a valid Owner signature and one more
  that fails is accepted by the text and rejected by the Rust, along with
  every commit citing it. Signatures are part of the object id, so such an
  authority is a different object from the one without the bad signature.
- **Not asked by an instance.** When `levcs-instance` decides who may read,
  it proves its current authority with `ChainVerifier::verify_chain`
  (`verify.rs:275`), which checks each step and not every signature. See
  "An instance proves its current authority by its steps alone" below.
- **Witnesses:** `div-b-authority-with-a-signature-that-does-not-verify`,
  and at an instance
  `div-be-an-instance-serves-under-an-authority-its-reader-refuses`.

### (c) An installed authority can put a commit on a conflicting lineage

- **Text:** a commit is on a conflicting lineage when it "cites an authority
  that is incomparable with this replica's canonical lineage" (D2).
- **Rust:** the authority a commit installs is classified as well
  (`history.rs:760`).
- **Effect:** a boundary commit that cites an authority on the replica's
  lineage and installs a rival successor is reported as conflicting, where
  the text read literally reports it as valid.
- **Witness:** `div-c-installing-an-authority-on-a-conflicting-lineage`.

### (d) Rewrites must be forced, and a deletion can be a rewrite

Two switches, `d-force` and `d-delete`.

- **Text:** "A non-fast-forward update also requires `Maintainer` in `A0`"
  (P.4). Nothing about a force flag, and nothing about deletion.
- **Rust:**
  - a non-fast-forward update must be marked as forced, whoever makes it
    (`admission.rs:697`);
  - deleting a ref whose target no remaining ref reaches is treated as a
    non-fast-forward update (`admission.rs:690`).
- **Effect:** read literally, any Contributor may delete an unprotected
  branch and unpublish its history. The Rust requires a Maintainer and a
  forced update.
- **Witnesses:** `div-d-rewrite-that-is-not-forced`,
  `div-d-deleting-a-ref-that-unpublishes`.

### (e) An ownerless successor is invalid wherever it is cited

- **Text:** H.5 rejects an ownerless successor where a commit installs it.
  D4 says "adopt rejection, per H.5, in verification", which can be read as
  covering only that.
- **Rust:** an ownerless successor is rejected anywhere in a chain
  (`history.rs:244`).
- **Effect:** a commit that cites an ownerless successor no commit ever
  installed is valid under the literal text and invalid in the Rust.
- **Not asked by an instance.** As for (b): the chain an instance proves
  before it lets a reader in may include a successor with no Owner.
- **Witnesses:** `div-e-ownerless-successor-cited-and-never-installed`, and
  at an instance
  `div-be-an-instance-serves-under-an-authority-its-reader-refuses`.

### (f) History on a conflicting lineage refuses a transfer

- **Text:** "Every received commit and release passes Rule H" (R.1). A
  commit on a conflicting lineage "is historically valid" (`verify`
  outcomes), so it passes. D2 has an incomparable lineage "detected" and
  reported "as valid on a conflicting lineage, not as invalid".
- **Rust:** `receive` in `levcs-cli` classifies what was sent against the
  source's current authority and refuses the whole transfer unless
  `HistoryReport::ok`, which requires that nothing be conflicting
  (`receive.rs:99`, `history.rs:92`). `pull`, `clone` and the read side of
  `fork` all go through it.
- **Effect:** a transfer is refused when the roots asked for reach a commit
  on a rival successor, the valid history behind those roots included. Read
  literally that history is received and the disagreement reported.
  - **`clone`** asks for every branch and release, so it fails while any of
    them is on the rival lineage.
  - **`pull`** with no branch named asks for every branch, and fails the
    same way.
  - **`pull` of named branches** (`fed_cmds.rs:411`) passes only those as
    roots. A branch that does not reach the rival lineage is still received.
    The witness shows both: c2 and c3 together are refused, c2 alone is
    recorded.
- **Note:** a source that has only ever admitted history under Rule P holds
  none. Property "everything published is valid history" has every
  published object on the lineage of `current`. So this bites on a source
  that took history in some other way: before these rules, by mirroring, or
  dishonestly.
- **What is compared:** `receive` itself, on every generated transfer, and
  the same two calls made directly.
- **Witness:** `div-f-receiving-history-on-a-conflicting-lineage`.

### (g) A current authority must be on the pinned chain

- **Text:** `current` is taken as given. "The lineage ending at that
  replica's accepted `current` is canonical" (D2); `A0` is
  `refs/authority/current` (Terms); and R.1 refuses a transfer for the chain
  of something received, which the source's own current authority is not.
- **Rust:** before anything else is read, the current authority must have
  an unbroken chain ending at the pinned genesis. `verify_history`
  (`history.rs:521`) and `admit` (`admission.rs:480`) each check it, and an
  instance checks it before it answers any read (`readers`,
  `levcs-instance/src/lib.rs:1051`).
- **Effect:** four places where the text read literally goes on and the
  Rust stops.
  - **Reading.** R.2 looks at the policy of the source's current authority,
    whatever that is: a public one lets anyone in. An instance serves no
    one, the public and the members alike, from a repository whose current
    authority it cannot follow back to the genesis the repository's id
    pins. It answers as if the repository did not exist.
  - **Replication.** A transfer of nothing from another repository is
    recorded as nothing, and valid history from a source whose current
    authority has a broken chain is recorded. The Rust refuses both.
  - **Publication.** A transaction that newly exposes nothing, such as a
    second branch on a published commit, is admitted on the signer's role in
    whatever authority is current. The Rust admits nothing over such a
    state. A transaction that gets as far as the check is refused as
    invalid, before any role is read; one that is not well formed, or is
    stale, is refused as that first.
  - **`verify`.** History is classified against the lineage ending at
    `current`, whatever that is, so with another repository's genesis as
    `current` every valid commit is on a conflicting lineage. The Rust
    reports the authority and classifies nothing against it.
- **Note:** Rule P never produces such a state: property "current moves one
  successor at a time" keeps `current` on the pinned chain. It can only come
  from outside the rules, which D6 and the bootstrap and mirror transitions
  allow for.
- **What is compared:** for `verify`, whether the current authority was
  reported is carried on the wire beside the verdicts.
- **Witnesses:** `div-g-a-source-that-is-not-the-repository-expected`,
  `div-g-publishing-over-a-current-that-does-not-stand`,
  `div-g-verify-with-another-repository-as-current`,
  `div-g-verify-with-a-broken-current`,
  `div-g-a-source-serves-no-one-under-an-authority-it-cannot-prove`.

### An instance proves its current authority by its steps alone

This is not a divergence from the text. It is two places in the Rust that
ask different things of the same authority, found by asking a real instance
for every generated read.

- **`verify_history` and `admit`:** an authority is one of the repository's
  if every step of its chain is a successor step, every signature on every
  authority in it verifies (b), and every successor in it has an Owner (e).
- **An instance deciding who may read:** every step is a successor step,
  and the chain ends at the genesis the id pins (g). Nothing more.
- **Effect:** a current authority that carries a signature that does not
  verify, or that has no Owner, is one `verify` and `admit` reject and an
  instance serves under. If that authority is public, anyone is sent the
  repository. The reader's `receive` then refuses the transfer, over the
  authority it was served under, so nothing is recorded; but the objects
  were sent.
- **How it can arise:** not by a push. `admit` refuses to install such an
  authority. It takes a repository that came to the instance some other
  way: before these rules, by mirroring, or by hand.
- **The model:** `serves` in `RuleR.hs` has the source follow the chain by
  its steps, with (b) and (e) left out there and nowhere else. Run without
  that, the instance and the model part ways within a hundred generated
  reads.
- **The decision it leaves:** whether an instance should prove its current
  authority as `verify` does, so that the two agree on what an authority of
  the repository is.
- **Witness:**
  `div-be-an-instance-serves-under-an-authority-its-reader-refuses`.

## Readings

- **Releases.** The release rule names the declarer's role and the
  predecessor's effective authority. The model also requires the declarer's
  signature to verify and the cited authority's chain to end at the pinned
  genesis. Without them the sentence admits an unsigned release under
  another repository's authority.
- **"Chain ends at the genesis" (H.2).** Taken to mean unbroken: every step
  back is a successor step, and the last authority is the pinned genesis.
- **Invalidity does not propagate.** A commit's verdict is its own. A parent
  enters only through `E(Pi)`, read off the parent whether or not the parent
  is valid.
- **Stale transactions.** "Evaluated against the single pre-transaction
  state" is taken to mean a transaction expecting a ref to hold something
  else is refused.
- **Protected refs (P.4).** The text says "a protected ref" and does not say
  what makes one. The model follows `README.md`: the policy
  `protected_branches` is a set of globs, a branch is protected when a glob
  matches its name or its full ref, and a release ref is never protected.
  The glob language is `?`, `*`, and `[…]` sets with ranges and `!`.
- **Reading a source with no current authority (R.2).** Nobody may. There
  is no policy to make it public and no authority to hold a role in.
- **What a transfer is (Rule R).** The genesis is the one the receiver
  expects and the roots are the ones it asked for; neither is taken from
  the source. Only what those roots reach is recorded, so pulling one
  branch does not bring the others. Cases: `r-only-what-was-asked-for`,
  `r-expecting-another-repository`.
- **A transfer of nothing.** With no roots there is no commit or release to
  fail Rule H. Read literally the empty set is recorded, from any source
  and whatever genesis was expected. Under (g) that holds only for a source
  that is the repository expected.
- **What a transaction is (Rule P).** The text does not say. Under both
  readings the model refuses, before anything else, a transaction that
  names a ref twice, names a branch or release with no name or with an
  empty, `.` or `..` component, or deletes a ref it expects to be absent.
  The Rust does the same. Case: `p-transaction-that-is-not-well-formed`.
- **A target of the wrong kind (Rule P).** A branch names a commit and a
  release ref a release. Anything else is refused under both readings,
  whoever asks. Case: `p-target-of-the-wrong-kind`.
- **A state is given, not judged (Rule P).** `S0` is an input. The
  precondition, stated on `admit`: its refs are branches at commits and
  release refs at releases, under names a ref can have. The model has no
  answer for any other state, and both ends of the wire refuse a request
  with one. The Rust does check: once a transaction is well formed, not
  stale, over a current authority on the pinned chain and signed by a
  Contributor, it is refused as invalid if a published ref is not a branch
  or release ref or does not lead to what it should. A transaction that
  fails one of the earlier checks is refused for that instead. None of this
  is compared. Two things about a state stay in scope: it may have no
  current authority (D6), and the one it has may be any authority at all
  (g).

## Untested contract requirements

- **A successor referenced outside the boundary.** The text adopts the push
  contract of `doc/instance-throughput-rewrite-plan.md` §6.1 unchanged. That
  contract says the successor authority, the boundary commit and the tree
  nodes binding `.levcs/authority` "are the only newly introduced
  authority-transition objects allowed to reference the successor", and
  rejects "unrelated successor references".
  - **Rust:** a commit that does not modify authority is refused if its tree
    carries an authority beyond `A0` (`admission.rs:810`).
  - **Model:** a commit records an installed authority only when it modifies
    authority, so the case cannot be expressed and neither side is tested on
    it. Testing it means giving a commit's tree its own field.
- **What an instance asks of a request, beyond R.2.** Read permission is
  compared: every generated read is asked of a real instance
  (`crates/levcs-cli/tests/spec_receive_support`), as `clone` asks, by no
  one in particular, by each key the scenario could have made a member, and
  by one it could not. Beyond its answer the instance is held to things
  R.2 must mean and the model does not say:
  - *One decision.* What it publishes, its refs, an object and a pack are
    all answered or none is, and what it publishes is what it holds.
  - *Holding a key is proving it.* Where a member reads what the public may
    not, a request naming the member's key and signed with another is
    refused, and so is one the member signed for a different read.
  - *What it sends.* A transfer it serves is kept as exactly what the roots
    reach, and a receiver that says what it holds is sent what it lacks.

  Not run: the rest of what the instance asks of a signed request, which is
  a clock within its skew and a nonce not seen before; a read while a push
  is part way, which the instance decides by the authority the push would
  replace; a `public_read` that is neither true nor false, which the model
  cannot express; the same gate where it decides who may push
  (`may_push`); and the check `fork` makes for itself in the CLI
  (`fed_cmds.rs:611`).
- **What `clone`, `pull` and `fork` do with a transfer.** `receive` is run,
  on every generated transfer, against a source that will say anything
  (`crates/levcs-cli/tests/spec_receive_support`). Beyond its answer it is
  held to things a transfer must do that are no part of the model:
  - *Of every call:* it asks the repository expected for exactly the roots,
    the genesis and the current authority, and says exactly what the
    receiver has. A refusal over intact objects must report no damage. A
    successful transfer is written to its destination, including when that
    store already holds some of the history. Its final object IDs and bytes
    are checked against the objects it held and everything the roots reach,
    trees and authorities included.
  - *Of every transfer:* asked for with roots named as `clone` names them,
    and as `pull` does where every root is a commit, it is kept or refused
    the same.
  - *Of every transfer kept:* a receiver that holds all of it accepts it
    from a source that sends none of that, and adds nothing. One that holds
    what the first root reaches accepts the rest, where there is more than
    one root. The same genesis offered for another repository's id is
    refused (`receive.rs:90`). And a receiver whose own copy of the first
    root is damaged refuses, where there is a root: two of the nine
    recorded transfers in the corpus have none.

  What is not run is the three commands. That each writes nothing when
  `receive` refuses, and which refs each records, is covered by hand and
  not by the generators: `clone` and `pull` in
  `crates/levcs-cli/tests/clone.rs`, a refused `fork` in `publication.rs`
  and a successful one in `fork.rs`. `pull` is tried here only as a
  receiver holding the genesis and nothing else, or one of the two cases
  above; what it says it has in a repository with history of its own is
  not generated. A real instance's choice of what to send is run where
  reads are, for a repository it serves.

## Gaps

The generators avoid each of these, so neither side is tested on it.

- **Genesis signature.** The Rust requires a genesis to be self-signed by an
  Owner. The text defines a genesis by its fields only.
- **`repo_id` on a successor.** The Rust requires it to equal the
  predecessor's. The model has no such field.
- **Commit signatures.** The Rust requires exactly one, by the key the
  commit names as author. The model has one signer and no separate author.
- **Order of refusals.** Which kind of refusal is given when several apply
  is the implementation's choice. The harness reproduces the order
  (`refusalKind` in `Wire.hs`) so that kinds can be compared exactly; it is
  not part of the rules. The order is: not a transaction, stale, no current
  authority, a current authority off the pinned chain (g), the signer's
  role (P.1), a target of the wrong kind, an unforced rewrite, a protected
  ref or a rewrite by a non-Maintainer, and then everything else.
- **Globs beyond the model's.** `**`, and a `-` or `]` used in a set in
  any way but the plain ones. The model treats `**` as matching nothing.
- **Patterns the policy cannot hold.** `protected_branches` is one string,
  the patterns joined by commas. An empty pattern, or one with a comma in
  it, has no such string, so the model's set of patterns and the Rust's
  would be different policies. Both ends of the wire refuse a request with
  one.
- **Numbers that are not a `u32`.** An object's number, a key and an
  authority's version are each a `u32` in the Rust's objects. Both ends of
  the wire refuse anything else, wherever it appears. So a version above
  `u32::MAX` is not a case either side answers.
- **One name given twice.** Two objects under one number, a key listed as
  a member twice, a state holding one ref twice. Both ends refuse them. A
  transaction naming a ref twice is different: that is judged.
- **References to nothing.** An object's id is the hash of what it names,
  so an object naming one that is missing, or one that names it back,
  cannot be made. The model would answer for a store like that, by treating
  a missing object as satisfying nothing. Both ends refuse it, and a
  request that asks about an object the store does not have.
- **Counts the format cannot hold.** More than 255 signatures or 65535
  members on an authority, more than 255 parents on a commit, and protected
  patterns that come to more than 65535 bytes once joined. Both ends refuse
  them.
- **Protected patterns are a set.** A pattern listed twice is one pattern.
  The Rust adapter joins the set, not the list it was given, so the two
  sides measure the same policy.
- **How a number is written.** A number is its value: `0`, `0.0` and `0e0`
  are the same, and both readers take all three. The value is taken exactly
  from the digits on both sides, so zero is zero at any exponent and
  `1.0000000000000000001` is not 1. One difference remains when an exponent
  overflows a machine word in aeson. For example, `1e18446744073709551616`
  reaches the model's reader as 1. The Rust reader refuses it.
- **How `verify`'s rejection of the current authority is read.**
  `HistoryReport` has no field for it. The oracle reads it from the report
  of the walk in question: a rule violation recorded against the current
  authority whose text begins "current authority". The wording is what
  tells it from the same authority reported where a commit installs it. If
  the wording changes the comparison fails; it cannot pass by mistake. A
  field on the report would remove the dependence, and that is a change to
  `levcs-identity` that has not been made.
- **Fork commits, damage, and tree completeness.** Not modelled.

## Consequences

- **No new root commit after the first membership change.** H.4 has a root
  commit cite the genesis, and P.2 has every newly exposed commit cite `A0`.
  Once `current` has moved off the genesis, a commit with no parents can
  never be published again, so a branch unrelated to existing history cannot
  be started. The text does not say this. Property: "a new root is published
  only under the genesis".
- **An emptied repository cannot be restarted.** The sharper form of the
  same thing. If the last authoritative branch or release ref is deleted
  after `current` has advanced, `R0` is empty. Any history is then newly
  exposed down to a root, and that root either cites the genesis, which is
  no longer `A0`, or breaks H.4. Ordinary publication can never resume.
  Property: "an emptied repository cannot be restarted once current has
  moved". Case: `p-emptied-repository-cannot-restart`, which the Rust
  agrees with.
- **"Every descendant cites `v2` or later" needs valid history in between.**
  H.3 relates a commit only to its parents. The claim about every descendant
  holds for a commit all of whose ancestors are valid, and is checked in
  that form.
- **The incomparable-merge check is implied by H.3.** No valid commit merges
  incomparable lineages, so the separate check at `history.rs:385` can only
  fire together with H.3. It changes the message, never the verdict.
- **An authority can be cited without ever being installed.** H.3 is a
  floor: a commit may cite any authority that descends from what its parents
  put in effect, whether or not any commit installed it. Rule P closes this
  for publication, since everything newly exposed cites `A0`. Rule R does
  not, so replicated history can contain it.

## Defects found on the way

- **Fixed oversized policy keys and values.** `AuthorityBody::normalize`
  used to skip the last policy entry when checking lengths. Encoding a
  lone 70,000-byte `protected_branches` value truncated its length field
  and produced an authority that failed to parse. Normalization now checks
  every key against the 255-byte limit and every value against the
  65,535-byte limit. The `policy_lengths_fit_their_wire_fields` test covers
  the round trip at both limits and rejects oversized entries in both the
  singleton and final positions.
- **Not fixed: an instance's pack leaves out what an installed authority
  reaches.** `closure` in `levcs-instance` (`lib.rs`, the walk behind
  `build_pack`) takes every tree entry a tree calls a blob to link to
  nothing. The authority a commit installs is such an entry, so it is sent
  and its predecessors are not followed from it. `verify_history`'s walk
  does follow them. In valid history nothing is lost: the predecessor of an
  installed authority is the authority its commit cites, and that is sent
  for the citation. Where a commit installs an authority that does not
  succeed the one it cites, the commit is invalid and the receiver refuses
  the transfer, as it should; but its refusal also names the predecessors
  it was not sent as objects that cannot be read, which blames the
  instance's copy for what the instance chose not to send. Found by the
  generated reads. The harness lets exactly that report through
  (`Transfer::behind_installed`) and no other damage.
