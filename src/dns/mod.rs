pub use self::aws::*;

mod aws;

/// Provides method to update DNS record on DNS server.
pub trait ServerClient {
    type Err: std::error::Error + 'static;

    fn set_txt(
        &self,
        fqdn: &str,
        value: &str,
        ttl: u32,
    ) -> impl Future<Output = Result<(), Self::Err>>;
}
