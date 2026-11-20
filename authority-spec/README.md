# Executable specification of the authority rules

Rules H, R and P of `doc/authority-semantics.md`, written as pure Haskell
functions over an abstract object model, and checked two ways:

- **against themselves:** properties the document claims, or that it would be
  a defect for the rules not to have;
- **against the implementation:** every generated scenario is rebuilt as real
  signed objects and put to `verify_history` and `admit` in `levcs-identity`,
  and the verdicts must match. A transfer is decided as `levcs-cli`'s
  `receive` decides one, from the same report.

The document stays normative. Where the Rust enforces something the document
does not say, the rule is a named switch, and `DIVERGENCES.md` records it.

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
```

The differential run reads three variables:

- **`LEVCS_SPEC_TESTS`**: scenarios per property. The default is 2000.
- **`LEVCS_SPEC_READING`**: the reading the Rust is held to.
  - `implemented`, the default: the ratified text plus every recorded
    divergence. This run must pass.
  - `ratified`: the text read literally. This run must fail.
  - `without:a`, `without:b`, `without:c`, `without:d-force`,
    `without:d-delete`, `without:e`, `without:f`, `without:g`: everything
    but one divergence. Each must fail, and shrinks to a smallest scenario showing
    that divergence.
- **`LEVCS_SPEC_ORACLE`**: a program to ask instead of the Rust oracle.

The harness can be checked against itself. `model-oracle` answers with the
model under the reading `LEVCS_SPEC_READING` names, so this must pass for
every reading:

```bash
cabal build model-oracle       # list-bin names the path whether or not it has been built
LEVCS_SPEC_ORACLE=$(cabal list-bin model-oracle) LEVCS_SPEC_READING=without:a cabal test differential
```

## Readings

`LeVCS.Authority.Reading` has one switch per recorded divergence.

- **`ratified`** has every switch off.
- **`implemented`** has every switch on.

The differential run holds the Rust to `implemented`. So what a passing run
says is exact: on the scenarios generated, the Rust implements the ratified
rules amended by the recorded divergences and nothing else.

## Comparing another implementation

The oracle is any program that reads one request per line and writes one
response per line. The wire format is `harness/LeVCS/Harness/Wire.hs`, and
every file in `corpus/` holds a request with its responses.

- **Against the generators:** point `LEVCS_SPEC_ORACLE` at the program and
  set `LEVCS_SPEC_READING` to the reading it implements.
- **Against the corpus:** each entry's `expect` is the answer under
  `implemented`, and `ratified` the answer under the literal text.
- **Against any other reading:** `model-oracle` gives the model's answer to
  a request under the reading `LEVCS_SPEC_READING` names.

A response is compared on six things only: which commits and releases were
given a verdict, which of those are invalid, which are on a conflicting
lineage, whether the replica's current authority was itself rejected, how
each transaction is decided, and whether each transfer is recorded and as
which objects. Reasons are shown when the two sides disagree and never
compared.

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

The object lists in a response are sets, and are compared as sets. The
decisions and the transfers are lists, each answering the request in its
place.

## What the model leaves out

- **Bytes, hashes and trees.** An object is a small integer; a signature is
  a key and whether it verifies; a commit records the authority it installs.
- **Damage.** Missing, corrupt and mis-typed objects.
- **Fork commits.** The document leaves them to their implemented rule.
- **Most of Rule R against the Rust.** The receiver's check (R.1, R.3) is
  compared: the oracle calls `verify_history` with the genesis expected and
  the source's current authority, and keeps or refuses on
  `HistoryReport::ok`, which is what `receive` in `levcs-cli` does. The
  generated transfers include ones no honest pair would make: any authority
  as the source's current one or as the genesis expected, and any of the
  roots or none. `receive` is not itself run, since it fetches from an
  instance. Read
  permission (R.2) is enforced in `levcs-instance` and the CLI, and is
  checked against the model only.
- **Wiring.** The differential run calls `verify_history` and `admit`
  directly. It cannot see a caller that hands either the wrong state, which
  is what audit finding C1 was.

## Saving a counterexample

A failing differential run prints the request as one line of JSON. To keep it
as a regression test:

```bash
cabal run write-corpus -- add <name> "<what it shows>" < request.json
```

The entry is written with the answers the rules give it, and `cargo test`
replays it from then on.
