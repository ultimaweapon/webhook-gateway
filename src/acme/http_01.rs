use instant_acme::KeyAuthorization;
use rustc_hash::FxHashMap;
use std::cell::{Cell, RefCell};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// Pending http-01 challenges.
#[derive(Default)]
pub struct HttpChallenges {
    challenges: RefCell<FxHashMap<String, KeyAuthorization>>,
    waiting: Cell<Option<Waker>>,
}

impl HttpChallenges {
    pub fn insert(&self, path: String, resp: KeyAuthorization) -> bool {
        use std::collections::hash_map::Entry;

        match self.challenges.borrow_mut().entry(path) {
            Entry::Occupied(_) => return false,
            Entry::Vacant(e) => e.insert(resp),
        };

        if let Some(w) = self.waiting.take() {
            w.wake();
        }

        true
    }

    pub fn remove(&self, path: &str) -> Option<KeyAuthorization> {
        self.challenges.borrow_mut().remove(path)
    }

    /// # Cancel safety
    /// This method is cancel safe.
    #[inline(always)]
    pub fn wait(&self) -> impl Future<Output = ()> {
        Wait { list: self }
    }
}

/// Future of [HttpChallenges::wait()].
struct Wait<'a> {
    list: &'a HttpChallenges,
}

impl<'a> Drop for Wait<'a> {
    #[inline]
    fn drop(&mut self) {
        self.list.waiting.set(None);
    }
}

impl<'a> Future for Wait<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.list.challenges.borrow().is_empty() {
            return Poll::Ready(());
        }

        // Register waker.
        self.list.waiting.set(Some(cx.waker().clone()));

        Poll::Pending
    }
}
