use serde::Deserialize;

/// Configuration for ACME.
#[derive(Deserialize)]
pub struct AcmeConfig {
    #[serde(default = "AcmeConfig::default_directory_url")]
    pub directory_url: Box<str>,
    pub domain: Box<str>,
    pub contact: Box<str>,
    pub accept_tos: bool,
    pub challenge: AcmeChallenge,
}

impl AcmeConfig {
    #[inline]
    fn default_directory_url() -> Box<str> {
        Box::from("https://acme-v02.api.letsencrypt.org/directory")
    }
}

/// Configuration for ACME challenge.
#[derive(Deserialize)]
#[serde(tag = "method")]
pub enum AcmeChallenge {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
}
