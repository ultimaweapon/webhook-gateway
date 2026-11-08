use super::ChallengeHandler;
use instant_acme::{AuthorizationHandle, ChallengeType, KeyAuthorization, RetryPolicy};
use rustc_hash::FxHashMap;
use std::cell::{Cell, Ref, RefCell};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

pub async fn challenge<'a>(
    challenges: &'a HttpChallenges,
    mut auth: AuthorizationHandle<'_>,
) -> Result<Box<dyn ChallengeHandler + 'a>, Box<dyn std::error::Error>> {
    // Add to list.
    let mut challenge = auth
        .challenge(ChallengeType::Http01)
        .ok_or_else(|| "the challenge is not available")?;
    let path = format!("/.well-known/acme-challenge/{}", challenge.token);
    let resp = challenge.key_authorization();
    let h = match challenges.insert(path.clone(), resp) {
        true => Handler {
            challenges,
            path,
            retry: RetryPolicy::new(),
        },
        false => return Err("challenge with the same token already exists".into()),
    };

    // Start.
    if let Err(e) = challenge.set_ready().await {
        return Err(erdp::wrap("couldn't start the challenge", e).into());
    }

    Ok(Box::new(h))
}

/// Implementation of [ChallengeHandler].
struct Handler<'a> {
    challenges: &'a HttpChallenges,
    path: String,
    retry: RetryPolicy,
}

impl<'a> Drop for Handler<'a> {
    fn drop(&mut self) {
        self.challenges.remove(&self.path);
    }
}

impl<'a> ChallengeHandler for Handler<'a> {
    fn retry_policy(&self) -> &RetryPolicy {
        &self.retry
    }
}

/// Pending http-01 challenges.
#[derive(Default)]
pub struct HttpChallenges {
    challenges: RefCell<FxHashMap<String, KeyAuthorization>>,
    waiting: Cell<Option<Waker>>,
}

impl HttpChallenges {
    pub fn get(&self, path: &str) -> Option<Ref<'_, KeyAuthorization>> {
        let challenges = self.challenges.borrow();

        Ref::filter_map(challenges, move |v| v.get(path)).ok()
    }

    fn insert(&self, path: String, resp: KeyAuthorization) -> bool {
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

    fn remove(&self, path: &str) -> Option<KeyAuthorization> {
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
