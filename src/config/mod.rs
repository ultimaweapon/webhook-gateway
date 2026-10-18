pub use self::acme::*;

use serde::Deserialize;

mod acme;

/// Program's configuration loaded from `etc/webhook-gateway/config.json`.
#[derive(Deserialize)]
pub struct Config {
    pub acme: AcmeConfig,
}
