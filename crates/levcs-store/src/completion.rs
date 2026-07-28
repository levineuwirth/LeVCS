//! Runtime-agnostic, one-to-many completion for submitted transactions.
//!
//! One in-flight transaction owns a [`SharedCompletion`]. Every caller that
//! coalesces onto that transaction obtains its own [`CompletionWaiter`], while
//! the shard writer publishes exactly one [`CompletionOutcome`].
//!
//! The outcome and waiter registrations deliberately share one mutex. A
//! waiter therefore cannot observe "not complete", lose the mutex, and
//! register after the only wake has already happened. Completion takes the
//! registered wakers while holding that mutex, then wakes them after releasing
//! it so arbitrary executor code never runs in the critical section.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use crate::types::{CommitReceipt, StoreError};

/// The one durable or definitive outcome shared by all attached callers.
pub type CompletionOutcome = Result<CommitReceipt, StoreError>;

/// One transaction's shared completion state.
///
/// Cloning this value clones only the `Arc`; it does not create a second
/// execution or a second outcome slot. [`SharedCompletion::complete`] accepts
/// the first outcome and treats any later attempt as a harmless no-op.
#[derive(Clone)]
pub struct SharedCompletion {
    shared: Arc<Shared>,
}

struct Shared {
    state: Mutex<State>,
}

struct State {
    outcome: Option<CompletionOutcome>,
    wakers: Vec<WaiterWaker>,
}

struct WaiterWaker {
    identity: Arc<()>,
    waker: Waker,
}

/// The exactly-once future belonging to one attached caller.
///
/// Dropping this value removes its registered waker without affecting the
/// transaction or any other waiter. Polling it after it has returned `Ready`
/// is a caller bug and panics with a stable diagnostic instead of attempting
/// to manufacture a second value.
#[must_use = "a completion waiter does nothing unless polled or awaited"]
pub struct CompletionWaiter {
    shared: Arc<Shared>,
    identity: Arc<()>,
    delivered: bool,
}

impl SharedCompletion {
    /// Creates an empty completion to be owned by one in-flight transaction.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    outcome: None,
                    wakers: Vec::new(),
                }),
            }),
        }
    }

    /// Attaches one caller to this transaction's outcome.
    ///
    /// Attachment remains valid after completion: its first poll observes the
    /// stored result immediately and requires no wake.
    pub fn subscribe(&self) -> CompletionWaiter {
        CompletionWaiter {
            shared: Arc::clone(&self.shared),
            identity: Arc::new(()),
            delivered: false,
        }
    }

    /// Publishes the outcome and wakes every currently registered waiter.
    ///
    /// Returns `true` when this call published the first outcome and `false`
    /// when the completion had already been signalled. No receiver is needed:
    /// completing after some or all waiters have dropped is successful and
    /// harmless.
    ///
    /// Wakers are invoked outside the state mutex. A panicking executor waker
    /// is isolated so it cannot unwind the shard thread or prevent another
    /// waiter from being woken.
    pub fn complete(&self, outcome: CompletionOutcome) -> bool {
        let wakers = {
            let mut state = self.shared.lock_state();
            if state.outcome.is_some() {
                return false;
            }

            state.outcome = Some(outcome);
            std::mem::take(&mut state.wakers)
        };

        for waiter in wakers {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                waiter.waker.wake();
            }));
        }

        true
    }

    #[cfg(test)]
    fn registered_waiters(&self) -> usize {
        self.shared.lock_state().wakers.len()
    }
}

impl Default for SharedCompletion {
    fn default() -> Self {
        Self::new()
    }
}

impl Shared {
    /// A poisoned completion mutex must not turn a committed transaction into
    /// a shard-thread panic. The protected state remains structurally valid
    /// because every mutation is an individual move or collection operation.
    fn lock_state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Future for CompletionWaiter {
    type Output = CompletionOutcome;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.delivered {
            panic!("CompletionWaiter polled after returning Ready");
        }

        let outcome = {
            let mut state = self.shared.lock_state();

            if let Some(outcome) = state.outcome.as_ref() {
                Some(outcome.clone())
            } else {
                match state
                    .wakers
                    .iter_mut()
                    .find(|registered| Arc::ptr_eq(&registered.identity, &self.identity))
                {
                    Some(registered) => {
                        if !registered.waker.will_wake(cx.waker()) {
                            registered.waker = cx.waker().clone();
                        }
                    }
                    None => state.wakers.push(WaiterWaker {
                        identity: Arc::clone(&self.identity),
                        waker: cx.waker().clone(),
                    }),
                }
                None
            }
        };

        match outcome {
            Some(outcome) => {
                self.delivered = true;
                Poll::Ready(outcome)
            }
            None => Poll::Pending,
        }
    }
}

impl Drop for CompletionWaiter {
    fn drop(&mut self) {
        if self.delivered {
            return;
        }

        let mut state = self.shared.lock_state();
        if let Some(index) = state
            .wakers
            .iter()
            .position(|registered| Arc::ptr_eq(&registered.identity, &self.identity))
        {
            state.wakers.swap_remove(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    use super::{CompletionWaiter, SharedCompletion};
    use crate::types::{CommitReceipt, OperationId, StoreError};

    #[derive(Default)]
    struct WakeCount {
        wakes: AtomicUsize,
    }

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PanickingWake;

    impl Wake for PanickingWake {
        fn wake(self: Arc<Self>) {
            panic!("executor waker panic");
        }
    }

    fn receipt(sequence: u64) -> CommitReceipt {
        CommitReceipt {
            operation_id: OperationId::from_bytes([7; 16]),
            repo_sequence: sequence,
            current_authority: levcs_core::ObjectId([11; 32]),
            refs: Vec::new(),
            objects_new: 3,
        }
    }

    fn poll_with(
        waiter: &mut CompletionWaiter,
        wake: &Arc<WakeCount>,
    ) -> Poll<Result<CommitReceipt, StoreError>> {
        let waker = Waker::from(Arc::clone(wake));
        let mut context = Context::from_waker(&waker);
        Pin::new(waiter).poll(&mut context)
    }

    fn assert_ready_ok(outcome: Poll<Result<CommitReceipt, StoreError>>, expected: &CommitReceipt) {
        match outcome {
            Poll::Ready(Ok(actual)) => assert_eq!(&actual, expected),
            other => panic!("expected a successful ready outcome, got {other:?}"),
        }
    }

    #[test]
    fn completion_after_first_poll_wakes_and_delivers() {
        let completion = SharedCompletion::new();
        let mut waiter = completion.subscribe();
        let wake = Arc::new(WakeCount::default());

        assert!(poll_with(&mut waiter, &wake).is_pending());
        assert_eq!(completion.registered_waiters(), 1);

        let expected = receipt(13);
        assert!(completion.complete(Ok(expected.clone())));
        assert_eq!(wake.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(completion.registered_waiters(), 0);
        assert_ready_ok(poll_with(&mut waiter, &wake), &expected);
    }

    #[test]
    fn completion_before_first_poll_is_immediately_ready() {
        let completion = SharedCompletion::new();
        let expected = receipt(21);
        assert!(completion.complete(Ok(expected.clone())));

        let mut waiter = completion.subscribe();
        let wake = Arc::new(WakeCount::default());
        assert_ready_ok(poll_with(&mut waiter, &wake), &expected);
        assert_eq!(wake.wakes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_waiter_delivers_exactly_once() {
        let completion = SharedCompletion::new();
        let mut waiter = completion.subscribe();
        let wake = Arc::new(WakeCount::default());
        assert!(completion.complete(Ok(receipt(34))));
        assert!(poll_with(&mut waiter, &wake).is_ready());

        let second_poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = poll_with(&mut waiter, &wake);
        }));
        assert!(second_poll.is_err());
    }

    #[test]
    fn multiple_waiters_receive_the_same_outcome() {
        let completion = SharedCompletion::new();
        let mut first = completion.subscribe();
        let mut second = completion.subscribe();
        let first_wake = Arc::new(WakeCount::default());
        let second_wake = Arc::new(WakeCount::default());

        assert!(poll_with(&mut first, &first_wake).is_pending());
        assert!(poll_with(&mut second, &second_wake).is_pending());

        let expected = receipt(55);
        assert!(completion.complete(Ok(expected.clone())));
        assert_eq!(first_wake.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(second_wake.wakes.load(Ordering::SeqCst), 1);
        assert_ready_ok(poll_with(&mut first, &first_wake), &expected);
        assert_ready_ok(poll_with(&mut second, &second_wake), &expected);
    }

    #[test]
    fn dropping_one_waiter_removes_only_its_waker() {
        let completion = SharedCompletion::new();
        let mut dropped = completion.subscribe();
        let mut retained = completion.subscribe();
        let dropped_wake = Arc::new(WakeCount::default());
        let retained_wake = Arc::new(WakeCount::default());

        assert!(poll_with(&mut dropped, &dropped_wake).is_pending());
        assert!(poll_with(&mut retained, &retained_wake).is_pending());
        assert_eq!(completion.registered_waiters(), 2);
        drop(dropped);
        assert_eq!(completion.registered_waiters(), 1);

        let expected = receipt(89);
        assert!(completion.complete(Ok(expected.clone())));
        assert_eq!(dropped_wake.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(retained_wake.wakes.load(Ordering::SeqCst), 1);
        assert_ready_ok(poll_with(&mut retained, &retained_wake), &expected);
    }

    #[test]
    fn completing_after_all_waiters_drop_is_harmless() {
        let completion = SharedCompletion::new();
        let mut first = completion.subscribe();
        let mut second = completion.subscribe();
        let first_wake = Arc::new(WakeCount::default());
        let second_wake = Arc::new(WakeCount::default());

        assert!(poll_with(&mut first, &first_wake).is_pending());
        assert!(poll_with(&mut second, &second_wake).is_pending());
        drop(first);
        drop(second);
        assert_eq!(completion.registered_waiters(), 0);

        assert!(completion.complete(Ok(receipt(144))));
        assert_eq!(first_wake.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(second_wake.wakes.load(Ordering::SeqCst), 0);
        assert!(!completion.complete(Ok(receipt(145))));
    }

    #[test]
    fn io_error_is_shared_losslessly_between_waiters() {
        let completion = SharedCompletion::new();
        let mut first = completion.subscribe();
        let mut second = completion.subscribe();
        let wake = Arc::new(WakeCount::default());
        let original = Arc::new(std::io::Error::other("one failure"));

        assert!(completion.complete(Err(StoreError::Io(Arc::clone(&original)))));
        let first_error = match poll_with(&mut first, &wake) {
            Poll::Ready(Err(StoreError::Io(error))) => error,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let second_error = match poll_with(&mut second, &wake) {
            Poll::Ready(Err(StoreError::Io(error))) => error,
            other => panic!("unexpected second outcome: {other:?}"),
        };

        assert!(Arc::ptr_eq(&original, &first_error));
        assert!(Arc::ptr_eq(&first_error, &second_error));
    }

    #[test]
    fn panicking_waker_cannot_unwind_completion_or_skip_other_waiters() {
        let completion = SharedCompletion::new();
        let mut panicking = completion.subscribe();
        let mut retained = completion.subscribe();
        let panic_waker = Waker::from(Arc::new(PanickingWake));
        let mut panic_context = Context::from_waker(&panic_waker);
        let retained_wake = Arc::new(WakeCount::default());

        assert!(Pin::new(&mut panicking)
            .poll(&mut panic_context)
            .is_pending());
        assert!(poll_with(&mut retained, &retained_wake).is_pending());

        let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            completion.complete(Ok(receipt(233)))
        }));
        assert!(matches!(completed, Ok(true)));
        assert_eq!(retained_wake.wakes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poisoned_state_mutex_does_not_panic_completion() {
        let completion = SharedCompletion::new();
        let shared = Arc::clone(&completion.shared);

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = shared.state.lock().expect("initial lock");
            panic!("poison completion state");
        }));
        assert!(poisoned.is_err());

        assert!(completion.complete(Ok(receipt(377))));
        let mut waiter = completion.subscribe();
        let wake = Arc::new(WakeCount::default());
        assert!(poll_with(&mut waiter, &wake).is_ready());
    }

    #[test]
    fn repeated_pending_polls_replace_instead_of_accumulating_wakers() {
        let completion = SharedCompletion::new();
        let mut waiter = completion.subscribe();
        let first_wake = Arc::new(WakeCount::default());
        let second_wake = Arc::new(WakeCount::default());

        assert!(poll_with(&mut waiter, &first_wake).is_pending());
        assert!(poll_with(&mut waiter, &second_wake).is_pending());
        assert_eq!(completion.registered_waiters(), 1);

        assert!(completion.complete(Ok(receipt(610))));
        assert_eq!(first_wake.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(second_wake.wakes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn completion_is_send_sync_and_waiter_is_send() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}

        assert_send_sync::<SharedCompletion>();
        assert_send::<CompletionWaiter>();
    }
}
