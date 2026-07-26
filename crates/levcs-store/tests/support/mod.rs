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
