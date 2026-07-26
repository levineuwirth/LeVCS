# Swarm fabric and IDE integration — roadmap exploration

**Status: non-binding first pass. This document decides nothing.**

It supersedes no plan, freezes no contract, and gates no work.
`doc/instance-throughput-rewrite-plan.md` remains the only authoritative roadmap, and
`doc/phase1-storage-spine-scope.md` remains the only authoritative Phase 1 scope. Nothing
here changes either until it is deliberately folded into them.

Written 2026-07-24, before the Wave A freeze review. If that review turns up something
structural in the frame or recovery model, it changes the sequencing conversation more
than anything in this document does, and this should be re-read afterward rather than
acted on before.

## 0. What prompted this

A proposal to make LeVCS the transactional substrate for a population of human and machine
contributors — thousands of speculative code states coexisting, being tested, synthesized,
audited, and selectively promoted without becoming thousands of branches — with an IDE as
the control room. Its flagship recommendation is "virtual swarm workspaces plus continuous
conflict radar" as the first non-Git-shaped feature.

The question this document answers is narrow: **if we incorporate some of it, what changes
about the roadmap?** Not whether the product direction is right.

## 1. What the existing plan already covers

More than the proposal assumes. This matters for sequencing, because it means most of the
substrate work is already scheduled rather than additional.

| Proposal asks for | Already in the plan |
|---|---|
| An event feed for IDE clients | §6.2 `GET /repos/{repo_id}/transactions?after={cursor}` — source-signed, hash-chained, fixed upper bound, typed `CursorExpired` |
| A stable contract for workflow tooling | §5.5, titled "Future instance software contract", naming review, CI, webhook, indexing, and workflow components as the consumers; `CommittedTransactionV1` frozen in Phase 0 for exactly this |
| Consumers that can fall behind and recover | §5.5 event low watermark, `CursorExpired` with the authenticated snapshot needed to rebuild, and Phase 3's exit requiring consumer feed/resnapshot tests |
| Parallel object ingestion instead of a per-repository mutex | The entire premise of this rewrite; §7's executor model and §5.2's group commit |
| Quarantine for untrusted agent objects | §4 identity invariant 7 — unreachable extras rejected, normal push never grants membership to pre-uploaded bytes |
| Bounded invisible staging that cannot publish | §8 `ProjectionStageSessionV1` — bounded, expiring, quota-accounted, sealing cannot publish membership, only `submit` may adopt |
| Not overloading the commit object | §5.5 keeps physical detail private and the commit compact; §13 "Format instability" says future workflow code binds only to logical snapshots and events |
| Repository identity independent of hosting | §4 identity invariant 2, and the federation model throughout §8 |

Two of these deserve emphasis.

**The signed feed is better than what the proposal asks for.** The proposal suggests SSE
"initially", then correctly says events should be notifications rather than trusted state.
The plan already has the trusted version: hash-chained, signed, page-bounded, with gap
detection via `previous_event_digest`. SSE belongs as a latency optimization *over* that
feed, never as a replacement for it. If SSE is ever added, the invariant to write down is
that a client must be able to reconstruct identical state from the signed feed alone, and
that no client action may depend on an SSE message it has not verified.

**Projection staging is most of an ephemeral workspace already.** It is bounded, invisible,
non-membership-granting, expiring, and debt-accounted. What it is not is *general*: §8
restricts it to initial mirror, resnapshot, oversized Full fork closure, and network
migration, and states plainly that normal push cannot reference it and it "is not an
ingestion loophole". Extending it to agent workspaces is a real scope amendment with real
security consequences, not a free reuse.

## 2. Where the proposal genuinely cuts against the plan

These are the items where a decision now is cheap and a decision later is expensive.

### 2.1 `levcsd` must not own ref transactions

The proposal lists ref transactions among the daemon's responsibilities. Definition of done
#1 is that *every* online or import mutation uses one validated, durable transaction
service, with verified byte-exact offline restore as the sole exception. A local daemon
writing refs directly would be a second mutation path — precisely what this rewrite exists
to eliminate.

Two acceptable shapes:

- `levcsd` **embeds** `StoreEngine` and *is* the transaction service for a local repository.
  §5.1's public API is already the embedding seam; this costs nothing.
- `levcsd` is a **client** of an instance and holds no authority of its own.

What is not acceptable is a daemon that sometimes writes through the store and sometimes
around it. Deciding this now is free; unwinding it after an IDE depends on the fast path
is not.

### 2.2 The ephemeral stratum must stay outside the durable service

The proposal's three-stratum split — canonical VCS, durable workflow, ephemeral
coordination — is right, and the third stratum is the one that will erode if it is not
written down as an invariant.

Heartbeats, cursors, intent leases, and conflict forecasts must never become a
`ValidatedTransaction`. A thousand agents heartbeating through group commit would spend the
75k budget on coordination noise and make every resource bound in §4 meaningless. Worse, it
would do so gradually and defensibly, one convenient exception at a time.

Proposed invariant, if this direction is taken:

> Ephemeral coordination state is never durable, never fenced, never federated, and never
> occupies a shard sequence. It is TTL-governed, bounded, and reconstructible from durable
> state after a restart. A feature that cannot tolerate losing it on process death does not
> belong in this stratum.

### 2.3 Delegation is identity-shaped, and identity freezes in Phase 2

§13's stop condition is explicit: do not encode authority transitions until their signed
logical contract is fixed in tests. Phase 2's **IdentitySession** builds the anchored
whole-graph verifier, the native/foreign fork-boundary rules, and the authority-transition
ordering rules. Adding scoped, expiring delegation certificates after that means reopening
the verifier.

We have direct evidence of what that costs. Contract review 2026-07-24-A corrected an
unsound recovery classification that had shipped past its own exit criteria. Contract review
2026-07-24-B had to be amended twice in one day — once for `validation_flags`, then again
for `verification.*`, which had the identical defect one block over. Both were cheap only
because nothing depended on them yet.

If delegation is wanted at all, its **contract** belongs in the Phase 2 freeze, even if no
code uses it until much later. Freezing an unused contract is nearly free. Retrofitting one
into a verifier with consumers is not.

### 2.4 Attestations do not fit `TransactionEvidenceV1`

`TransactionEvidenceV1` is per-transaction and describes the *source of a mutation* —
client, mirror, migration, projection admin, administrative. It is one-to-one with a frame
and is bound into the state digest.

An attestation is a different shape entirely:

| | Evidence | Attestation |
|---|---|---|
| Subject | The transaction it accompanies | A tree, commit, proposal, or integration node |
| Cardinality | Exactly one per transaction | Many per subject, unbounded over time |
| Producer | The mutating principal | Third parties, often much later |
| Timing | Before append, bound into the frame | Any time after the subject exists |
| Retention | Tied to the transaction | Independent; a benchmark result may outlive interest in it |

Forcing attestations into the evidence union would corrupt a frozen contract to fit a
different lifetime. The proposal's signed artifact envelope is the right answer and matches
the plan's existing instinct to keep the commit object small — but it is a **new signed
object class**, so it is a new frozen contract rather than an extension of one.

### 2.5 The canonical workload is the wrong benchmark for swarm scale

`bench/workloads/small-commit.toml` is frozen and measures new, valid, durably acknowledged
commits per second, with an elaborate anti-gaming apparatus protecting the 60k claim.

A swarm workload is a different animal: mostly overlay writes and merge previews, heavy
reads, comparatively few commits. Measuring it against `small-commit.toml` would either
understate it or, worse, invite loosening the canonical workload's rules to accommodate it.

If swarm scale becomes a goal it needs a **second frozen workload** with its own gates and
its own `gate` enum value — additive, never a modification of the canonical one. §3 already
establishes the precedent that a storage primitive result can never be promoted to an
instance throughput claim; the same firewall applies here.

## 3. The roadmap delta, by phase

### Phases 0 and 1 — no change

The storage spine is agnostic to all of this. It stores namespaced objects, refs, and
evidence behind one durability fence. Nothing in the proposal needs a different journal
format, a different recovery model, or a different index.

Wave A is at its freeze review as this is written. Perturbing it now would be the worst
available timing, and there is no benefit to doing so: every item below lands in Phase 2 or
later.

### Phase 2 — three contract freezes and one scope amendment

Added to the Phase 2 lead freeze, alongside ProtocolV2 rather than after it:

1. **Delegation certificate contract** — issuer, ephemeral subject key, repo, run, expiry,
   allowed base refs, allowed operations, path or symbol scopes, commit ceiling, publication
   rights, signature. Frozen with golden vectors and adversarial fixtures; no implementation
   required in Phase 2 beyond what IdentitySession needs to not preclude it.
2. **Artifact envelope contract** — kind, schema version, subject IDs, dependency IDs,
   issuer key, timestamp, payload, signature, with typed payloads for proposal, attestation,
   review, integration plan, and supersession. The kernel stays small; the payload schemas
   evolve independently.
3. **Attestation subject binding** — how an attestation names its subject (tree, commit,
   proposal, integration node) and what makes it independently verifiable: environment
   digest, command digest, input dependency closure, result, payload hash.

Plus one amendment: **extend §8 projection staging's permitted uses** to cover ephemeral
agent workspaces. Today §8 enumerates mirror, resnapshot, oversized Full fork, and network
migration, and states that normal push cannot reference a session. Widening that list is a
security-relevant change and needs its own adversarial fixtures — the existing ones prove
that no partial or abandoned session affects membership, reads, dedupe, refs, receipts, or
events, and that property must survive the widening.

Estimated cost: a few days of contract work. It buys the option without putting any
throughput gate at risk.

### Phase 3 — two cheap additions

- **Structured machine output** for status, log, diff, refs, authority, and merge
  explanation. Prerequisite for any IDE client, and useful independently.
- **SSE transport over the existing signed feed**, with the invariant from §1: a client must
  be able to reconstruct identical state from the signed feed alone.

Phase 3's exit already requires consumer feed and resnapshot tests, so the hard part is
scheduled.

### New phase after Phase 3 — the swarm substrate

`levcsd`, overlay workspaces, lazy materialization, and conflict radar. Gated on P3 passing,
for the reason in §5 below.

This is where the proposal's flagship lives, and notably it needs Phases 1, 2, and 3 and
almost nothing from Phases 4 and 5. That is a genuine reordering opportunity, discussed
below.

### Phases 4 and 5 — mostly unchanged, with one new load

Federation already replicates signed objects, so attestations and artifacts travel free if
they are objects.

Compaction gains a real new requirement. §5.4 reasons about events, refs, and object
dependency retention. It does not reason about ten thousand expired agent overlays, which
would become a major reclamation consumer with a very different access pattern —
short-lived, bursty, and almost entirely garbage. §5.4's grace rules use committed insertion
sequence and time rather than file mtime, which is the right foundation, but the debt
accounting and low-watermark behavior would need to be re-derived for that load.

## 4. Where the proposal is wrong or underweights something

Recording these so they are not silently absorbed.

**"levcsd owns ref transactions."** Addressed in §2.1. This is the one item in the proposal
that would break a definition-of-done clause if implemented literally.

**"Add an event feed... using Server-Sent Events initially."** The plan already has a
stronger feed. SSE is a transport, not the contract. The proposal half-recognizes this two
sentences later; the correction is to make the signed feed primary by construction rather
than by convention.

**The `levcs-core` index critique is accurate but out of scope for this plan.** The sorted
`Vec` with linear lookup and the double working-tree walk in `status` are real, but they are
*client-side*. The instance rewrite deliberately scoped itself to the instance. See §5.2.

**"Parallelize object ingestion... the instance currently uses a per-repository serializing
mutex."** This is a description of the problem we are already 1.5 phases into fixing. Worth
noting only because it means the proposal's scalability section is largely satisfied by work
already scheduled.

**The 255-parent commit limit** is correctly identified as a non-issue for the integration
forest, since the forest's whole point is that no node has a thousand parents. No change.

**"Confidence should not initially be an LLM opinion."** Agreed and worth preserving as a
principle. The proposal's list of deterministic inputs — cascade success, handler used,
syntax validity, type checking, test deltas, same-symbol edits, interface changes — is
computable from artifacts the plan already produces or could produce cheaply. Keeping the
AI boundary at "proposes and explains, never decides or signs" matches the original
specification's instinct and should be written into whatever phase owns this.

## 5. Sequencing risk

### 5.1 The failure mode to avoid

The discipline that makes the current plan good is that it refuses claims without archived
reproducible evidence, and it has an explicit stop condition for this exact failure: §13's
"Custom journal correctness — stop performance work if crash invariants are not mechanically
testable."

The analogous risk here is starting the exciting layer before the boring one is proven and
finishing neither. A swarm fabric on an unproven storage engine gives you a demo that cannot
be trusted and an engine that never gets its gates run.

The flagship needing nothing from Phases 4 and 5 makes reordering *tempting* specifically
because it looks free. It is not free: P4 and P5 are where power-loss, compaction
interference, and soak behavior get proven, and those are exactly the properties a swarm
workload stresses hardest.

**Recommendation: take the Phase 2 contract freezes now, and gate everything else on P3.**
That is the smallest commitment that preserves the option.

### 5.2 An unhomed workstream

The client-side index and working-tree scanning work has **no home on the current roadmap**.
It is not in the instance rewrite, which is correctly scoped to the instance, and it is not
in any other document.

It becomes load-bearing the moment an IDE does incremental analysis over live buffers: a
linear-lookup index and a double tree walk per status are fine for a CLI invocation and
untenable for a daemon serving an editor at keystroke latency.

If the IDE direction is taken, this needs to become a real phase somewhere, with its own
scope. Flagging it here rather than assuming it will be absorbed.

### 5.3 What the swarm workload does to the throughput claim

Worth thinking through before any of this is committed to.

The rewrite's headline is 60k durable commits/s. The proposal argues agents should
*not* produce commits — ephemeral overlays instead, with only worthwhile results promoted.
Taken seriously, that reduces commit pressure and increases pressure on:

- Overlay writes and staging session churn (bounded by §8's quotas, which were sized for
  mirror transfers, not for thousands of concurrent small sessions).
- Merge previews, which are CPU-bound tree-sitter work on the validation pool.
- Reads against many concurrent snapshots, each pinning a generation and holding segments
  against reclamation.

That last one is the interesting risk. §6.2's snapshot lease machinery has per-principal and
global ceilings on lease count, pinned bytes, duration, and compaction debt. A swarm holding
hundreds of concurrent workspace snapshots is a lease-pressure workload nobody has sized.
It is not obviously a problem, but it is unmeasured, and it is the kind of thing that shows
up as compaction starvation under soak rather than as an obvious failure.

## 6. Open questions

Not to be answered now.

1. Does `levcsd` embed `StoreEngine` or client an instance? (§2.1 — both are acceptable;
   the hybrid is not.)
2. Is delegation wanted at all, or is per-agent key issuance under an existing authority
   acceptable for the first iteration? The contract freeze is cheap; the verifier work is
   not.
3. Do ephemeral workspaces reuse projection staging, or get their own bounded mechanism?
   Reuse is less code and more risk, since staging's security properties were proved for a
   narrower set of callers.
4. Second benchmark workload: what does it actually measure, and what are its gates? "Swarm
   throughput" is not yet a number anyone could pass or fail.
5. Where does the client-side index work live? (§5.2.)
6. What is the smallest demonstration that would be worth building — and is it the
   proposal's ten-step one, or something smaller that proves the same thing?

## 7. Summary

- **Phases 0 and 1: no change.** Do not perturb Wave A.
- **Phase 2: three contract freezes** (delegation, artifact envelope, attestation subject
  binding) **and one scope amendment** (§8 staging uses). This is the only part where
  deferral is genuinely expensive, and it is a few days of work.
- **Phase 3: structured output and SSE-over-signed-feed.** Cheap, independently useful.
- **New phase after Phase 3** for `levcsd`, workspaces, and conflict radar, gated on P3.
- **Phases 4 and 5 stand**, with compaction gaining an ephemeral-debris workload it has not
  been designed against.
- **One unhomed workstream** — client-side index and incremental scanning — needs a home if
  the IDE direction is taken.
- **One invariant worth writing down early** — ephemeral coordination never enters the
  durable transaction service.

None of this is binding. Revisit after the Wave A freeze review.
