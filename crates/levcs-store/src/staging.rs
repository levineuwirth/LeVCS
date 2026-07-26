//! Bounded invisible projection-staging sessions: begin, idempotent chunk-put,
//! read-only resolver, seal to `StagedProjectionInstallV1`, abort, expiry, and
//! cleanup.
//!
//! **Owned by B1 NamespaceTxn** (scope 2.1, 6-B1). Empty in D0.
//!
//! Sealing cannot publish membership. Only `submit(ValidatedTransaction)` may
//! adopt a sealed descriptor, so possession of a session ID never authorizes
//! publication (plan §4 identity invariant 7, §8).
