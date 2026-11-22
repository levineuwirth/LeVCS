# Executable specification of the authority rules

Rules H, R and P of `doc/authority-semantics.md`, written as pure Haskell
functions over an abstract object model, and checked two ways:

- **against themselves:** properties the document claims, or that it would be
  a defect for the rules not to have;
- **against the implementation:** every generated scenario is rebuilt as real
  signed objects and put to `verify_history` and `admit` in `levcs-identity`,
  and the verdicts must match. Every transfer is also made for real, by the
  `receive` in `levcs-cli` that `clone`, `pull` and `fork` call, and every
  read is asked of a real instance of `levcs-instance`.

The document stays normative. Where the Rust enforced something the document
did not say, the rule is a named switch, and `DIVERGENCES.md` records it.
The document was amended on 2026-11-21 to say all of them, so the reading
called `amended` below is the document as it stands, and the one called
`unamended` is the document as first ratified, on 2026-10-04.

## Layout

| Path | What it is |
|---|---|
| `src/LeVCS/Authority/` | The specification: `Model`, `RuleH`, `RuleR`, `RuleP`, and `Reading` (the switches). Depends on `base` and `containers` only. |
| `harness/LeVCS/Harness/` | Scenario scripts, Hedgehog generators, the JSON wire format, and the named cases. |
| `test/Properties.hs` | The rules against themselves. No Rust involved. |
| `test/Differential.hs` | The rules against `levcs-identity`, or any other oracle. |
| `app/WriteCorpus.hs` | Writes `corpus/` from the named cases. |
| `app/ModelOracle.hs` | The model answering as an oracle, under any reading. |
| `corpus/` | The named cases as JSON, with the specified answers. |
| `../crates/levcs-identity/examples/spec_oracle.rs` | The Rust oracle the differential run drives. |
| `../crates/levcs-identity/tests/spec_corpus.rs` | Replays `corpus/` in `cargo test`. Needs no Haskell. |
| `../crates/levcs-cli/examples/spec_receive_oracle.rs` | A second Rust oracle, with every transfer made by `receive` and every read asked of an instance. |
| `../crates/levcs-cli/tests/spec_receive.rs` | Replays the transfers and reads of `corpus/` in `cargo test`. |

## Running

From this directory, with GHC 9.10 and cabal 3.16 (GHC 9.6 also builds it,
without the freeze file):

```bash
cabal test properties          # the rules against themselves, and the corpus against the rules
cabal test differential        # the rules against levcs-identity; builds the oracle through cargo
cabal run write-corpus         # rewrite corpus/ from the named cases
```

From the repository root, with no Haskell toolchain:

```bash
cargo test -p levcs-identity --test spec_corpus
cargo test -p levcs-cli --test spec_receive
```

The differential run asks two oracles. The first is `spec_oracle` in
`levcs-identity`, for Rules H and P. The second is `spec_receive_oracle` in
`levcs-cli`, for Rule R: it answers the same requests, with every transfer
made by `receive`, and it answers reads, each asked of an instance of
`levcs-instance` that holds the scenario. The first oracle has no instance
and says nothing of reads. The run reads these variables:

- **`LEVCS_SPEC_TESTS`**: scenarios per property. The default is 2000.
- **`LEVCS_SPEC_READING`**: the reading the Rust is held to.
  - `amended`, the default: the text as it stands, which is the text as
    first ratified plus every recorded divergence. This run must pass.
  - `unamended`: the text as first ratified, read literally. This run must
    fail.
  - `without:a`, `without:b`, `without:c`, `without:d-force`,
    `without:d-delete`, `without:e`, `without:f`, `without:g`: everything
    but one divergence. Each must fail, and shrinks to a smallest scenario showing
    that divergence.
- **`LEVCS_SPEC_ORACLE`**: a program to ask instead of the first oracle.
  With this set, the second oracle is not asked at all unless it is named
  too: the program is some other implementation, and `levcs-cli` has no
  part in the run.
- **`LEVCS_SPEC_RECEIVE_ORACLE`**: a program to ask instead of the second.
- **`LEVCS_SPEC_SCRATCH`**: read by the second oracle. Where it keeps the
  objects a transfer writes, for as long as that transfer takes. The default
  is `/dev/shm` where there is one. The object store makes every write
  durable, and on a disk that is most of what a run costs.

The harness can be checked against itself. `model-oracle` answers with the
model under the reading `LEVCS_SPEC_READING` names, so this must pass for
every reading:

```bash
cabal build model-oracle       # list-bin names the path whether or not it has been built
LEVCS_SPEC_ORACLE=$(cabal list-bin model-oracle) LEVCS_SPEC_READING=without:a cabal test differential
```

## Readings

`LeVCS.Authority.Reading` has one switch per recorded divergence.

- **`unamended`** has every switch off: the text as first ratified.
- **`amended`** has every switch on: the text as it stands.

The differential run holds the Rust to `amended`. So what a passing run
says is exact: on the scenarios generated, the Rust implements the rules as
first ratified, amended by the recorded divergences and nothing else.

## Comparing another implementation

The oracle is any program that reads one request per line and writes one
response per line. The wire format is `harness/LeVCS/Harness/Wire.hs`, and
every file in `corpus/` holds a request with its responses.

- **Against the generators:** point `LEVCS_SPEC_ORACLE` at the program and
  set `LEVCS_SPEC_READING` to the reading it implements.
- **Against the corpus:** each entry's `expect` is the answer under
  `amended`, and `unamended` the answer under the text as first ratified,
  read literally.
- **Against any other reading:** `model-oracle` gives the model's answer to
  a request under the reading `LEVCS_SPEC_READING` names.

A response is compared on seven things only: which commits and releases
were given a verdict, which of those are invalid, which are on a
conflicting lineage, whether the replica's current authority was itself
rejected, how each transaction is decided, whether each transfer is
recorded and as which objects, and what each read comes to: sent nothing,
sent history that is kept, or sent history that is refused. Reasons are
shown when the two sides disagree and never compared.

Some requests are answered by neither side, because the implementation's
objects could not hold them and the two sides would be answering different
questions:

- **Protected patterns:** the policy is one comma-separated string of at
  most 65535 bytes, so a pattern is never empty and never has a comma in
  it. The patterns are a set: one listed twice is one pattern.
- **Numbers:** an object's number, a key and a version are each a `u32`,
  wherever they appear. It is the value that counts, however it is written,
  and it is taken exactly from the digits: `0.0` and `0e2000` are 0, and
  `1.0000000000000000001` is not 1. `DIVERGENCES.md` records the remaining
  difference when an exponent overflows a machine word in aeson.
- **Names given twice:** no number names two objects, no key is a member
  twice, and no state holds a ref twice.
- **References:** everything named is in the store, and nothing is behind
  itself. The numbers say nothing of order: an object may have a lower
  number than what it refers to.
- **Counts:** an authority carries at most 255 signatures and 65535
  members, and a commit at most 255 parents.
- **States:** a state's refs are branches at commits and release refs at
  releases, under names a ref can have. A transaction may name anything;
  that is for the rules to judge.
- **Reads:** a read is asked of a repository by its id, and the id is
  derived from a genesis. So where a request asks reads, its pin is a
  genesis.

The object lists in a response are sets, and are compared as sets. The
decisions and the transfers are lists, each answering the request in its
place.

## What the model leaves out

- **Bytes, hashes and trees.** An object is a small integer; a signature is
  a key and whether it verifies; a commit records the authority it installs.
- **Damage.** Missing, corrupt and mis-typed objects.
- **Fork commits.** The document leaves them to their implemented rule.
- **Parts of a request that are not R.2.** The receiver's side of Rule R
  (R.1, R.3) is compared twice: from the report of `verify_history`, and by
  running `receive` in `levcs-cli` against a source that will say anything.
  That source sends every object of the scenario whatever was asked for,
  and the generated transfers include ones no honest pair would make: any
  authority as the source's current one or as the genesis expected, and any
  of the roots or none. The source's side (R.2) is compared by asking a
  real instance, which decides for itself whom to answer and what to send.
  What an instance asks of a signed request besides the signature, its
  clock and its nonce, is not run, nor a read while a push is part way.
- **Wiring, for publication.** `receive` is run with roots named as each of
  its three callers names them. The differential run still calls
  `verify_history` and `admit` directly, so it cannot see a caller that
  hands `admit` the wrong state, which is what audit finding C1 was. Nor
  are `clone`, `pull` and `fork` themselves run: what each does with what
  `receive` returns is theirs, and is tested by hand. `DIVERGENCES.md`
  says where.

## Saving a counterexample

A failing differential run prints the request as one line of JSON. To keep it
as a regression test:

```bash
cabal run write-corpus -- add <name> "<what it shows>" < request.json
```

The entry is written with the answers the rules give it, and `cargo test`
replays it from then on.
