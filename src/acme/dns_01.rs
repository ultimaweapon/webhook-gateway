use super::ChallengeHandler;
use crate::dns::ServerClient;
use instant_acme::{AuthorizationHandle, ChallengeType, RetryPolicy};

pub async fn challenge<T: ServerClient>(
    client: &T,
    mut auth: AuthorizationHandle<'_>,
) -> Result<Box<dyn ChallengeHandler>, Box<dyn std::error::Error>> {
    // Set DNS record.
    let mut challenge = auth
        .challenge(ChallengeType::Dns01)
        .ok_or_else(|| "the challenge is not available")?;
    let fqdn = format!("_acme-challenge.{}", challenge.identifier());
    let mut key = challenge.key_authorization().dns_value();

    key.insert(0, '"');
    key.push('"');

    if let Err(e) = client.set_txt(&fqdn, &key, 60).await {
        return Err(erdp::wrap("couldn't update DNS server", e).into());
    }

    // Start.
    if let Err(e) = challenge.set_ready().await {
        return Err(erdp::wrap("couldn't start the challenge", e).into());
    }

    Ok(Box::new(Handler(RetryPolicy::new())))
}

/// Implementation of [ChallengeHandler].
struct Handler(RetryPolicy);

impl ChallengeHandler for Handler {
    fn retry_policy(&self) -> &RetryPolicy {
        &self.0
    }
}
