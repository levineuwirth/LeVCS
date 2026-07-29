//! Shared harness support for A3's Phase 1 crash and benchmark work.
//!
//! `group_model` is the group-aware failpoint model of scope 4-A3 deliverable
//! 3. `harness` is plumbing: fixture loading and child-process driving.
//!
//! Neither module is compiled into a release binary; both live under `tests/`
//! because scope 2.1 gives A3 no `src/**` file. See the note on
//! `group_model::group_failpoint_expectation` about where the scope text says
//! this function lives.

pub mod group_model;
pub mod harness;

/// The Wave B submit-path harness (scope 6.6 deliverable 2).
///
/// Gated on `store-privileged` because building a `ValidatedTransaction` at
/// all requires `PrivilegedConstruction`, which scope 2.2 deliberately makes
/// unreachable without that feature. The Phase 1 gate runs
/// `failpoints,store-internals,store-privileged`, so the eight Wave B rows are
/// exercised on every gate run; `crash_matrix::the_submit_path_rows_are_driven_
/// in_this_configuration` fails loudly rather than passing silently if they
/// are not.
#[cfg(feature = "store-privileged")]
pub mod engine_matrix;
