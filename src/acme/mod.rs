use self::aws::Route53;
use self::http_01::HttpChallenges;
use crate::config::{AcmeChallenge, AcmeConfig, AcmeDns01};
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use bytes::Bytes;
use erdp::ErrorDisplay;
use http::header::ALLOW;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use instant_acme::{
    Account, AuthorizationHandle, AuthorizationStatus, AuthorizedIdentifier, ChallengeType,
    Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use std::convert::Infallible;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::pin;
use std::rc::Rc;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::yield_now;
use tokio::time::sleep_until;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

mod aws;
mod http_01;

/// Provides methods to request TLS certificate from ACME provider.
pub struct Acme {
    account: Account,
    challenge: Challenge,
}

impl Acme {
    pub async fn new(
        config: &AcmeConfig,
        tasks: &TaskTracker,
        running: &CancellationToken,
    ) -> Result<Self, AcmeError> {
        // Get account.
        let account = Account::builder().map_err(AcmeError::CreateAccountBuilder)?;
        let path = PathBuf::from_iter(["etc", "webhook-gateway", "acme-credentials.bin"]);
        let account = match std::fs::read(path.as_path()) {
            Ok(v) => match minicbor_serde::from_slice(&v) {
                Ok(v) => match account.from_credentials(v).await {
                    Ok(v) => v,
                    Err(e) => return Err(AcmeError::LoadAccount(path, e)),
                },
                Err(e) => return Err(AcmeError::LoadCredentials(path, e)),
            },
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // Build request.
                let contact = format!("mailto:{}", config.contact);
                let req = instant_acme::NewAccount {
                    contact: &[contact.as_str()],
                    terms_of_service_agreed: config.accept_tos,
                    only_return_existing: false,
                };

                // Create.
                let url = config.directory_url.as_ref();
                let (acc, cred) = account
                    .create(&req, url.into(), None)
                    .await
                    .map_err(AcmeError::CreateAccount)?;

                // Save credentials.
                let cred = minicbor_serde::to_vec(cred).unwrap();

                if let Err(e) = std::fs::write(path.as_path(), cred) {
                    return Err(AcmeError::SaveCredentials(path, e));
                }

                acc
            }
            Err(e) => return Err(AcmeError::ReadCredentials(path, e)),
        };

        drop(path);

        // Set up challenge handler.
        let challenge = match &config.challenge {
            AcmeChallenge::Http01 => {
                // Create HTTP server.
                let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                let addr = SocketAddr::new(ip, 80);
                let http = match TcpListener::bind(&addr).await {
                    Ok(v) => v,
                    Err(e) => return Err(AcmeError::CreateHttpServer(addr, e)),
                };

                // Configure HTTP server.
                let hyper = hyper::server::conn::http1::Builder::new();

                // Start HTTP server.
                let challenges = Rc::new(HttpChallenges::default());

                tasks.spawn_local(Self::run_http(
                    tasks.clone(),
                    http,
                    hyper,
                    challenges.clone(),
                    running.clone(),
                ));

                Challenge::Http01(challenges)
            }
            AcmeChallenge::Dns01(AcmeDns01::Aws { hosted_zone }) => {
                let crypto = CryptoMode::Ring;
                let http = aws_smithy_http_client::Builder::new()
                    .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(crypto))
                    .build_https();
                let config = aws_config::from_env().http_client(http).load().await;
                let client = aws_sdk_route53::Client::new(&config);

                Challenge::Dns01(DnsServer::Aws(Route53::new(client, hosted_zone.clone())))
            }
        };

        Ok(Self { account, challenge })
    }

    pub async fn order(&self, domain: &str) -> Result<(String, String), OrderError> {
        // Create new order.
        let mut order = self
            .account
            .new_order(&NewOrder::new(&[Identifier::Dns(domain.into())]))
            .await
            .map_err(OrderError::CreateOrder)?;

        // Authorize.
        let mut auths = order.authorizations();

        while let Some(auth) = auths.next().await {
            let auth = auth.map_err(OrderError::RetrieveAuth)?;

            if auth.status != AuthorizationStatus::Pending {
                continue;
            }

            // Start challenge.
            let retry = match &self.challenge {
                Challenge::Http01(v) => Self::challenge_http_01(v, auth)
                    .await
                    .map_err(|e| OrderError::Challenge("http-01", e))?,
                Challenge::Dns01(DnsServer::Aws(v)) => Self::challenge_dns_01(v, auth)
                    .await
                    .map_err(|e| OrderError::Challenge("dns-01", e))?,
            };

            drop(auths);

            // Wait for ready.
            loop {
                match order.poll_ready(&retry).await {
                    Ok(OrderStatus::Ready) => break,
                    Ok(v) => return Err(OrderError::UnexpectedOrderStatus(v)),
                    Err(instant_acme::Error::Timeout(Some(v))) => sleep_until(v.into()).await,
                    Err(e) => return Err(OrderError::RetrieveOrderStatus(e)),
                }
            }

            break;
        }

        // Get private key and certificate.
        let key = order
            .finalize()
            .await
            .map_err(OrderError::RetrievePrivateKey)?;
        let crt = order
            .poll_certificate(&Default::default())
            .await
            .map_err(OrderError::RetrieveCert)?;

        Ok((crt, key))
    }

    async fn challenge_http_01(
        challenges: &HttpChallenges,
        mut auth: AuthorizationHandle<'_>,
    ) -> Result<RetryPolicy, Box<dyn std::error::Error>> {
        // Add to list.
        let mut challenge = auth
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| "the challenge is not available")?;
        let path = format!("/.well-known/acme-challenge/{}", challenge.token);
        let resp = challenge.key_authorization();

        if !challenges.insert(path.clone(), resp) {
            return Err("challenge with the same token already exists".into());
        }

        // Start.
        if let Err(e) = challenge.set_ready().await {
            let e = erdp::wrap("couldn't start the challenge", e);

            challenges.remove(&path);

            return Err(e.into());
        }

        Ok(RetryPolicy::new())
    }

    async fn challenge_dns_01<T: Dns01>(
        server: T,
        mut auth: AuthorizationHandle<'_>,
    ) -> Result<RetryPolicy, Box<dyn std::error::Error>> {
        // Set DNS record.
        let mut challenge = auth
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| "the challenge is not available")?;
        let domain = challenge.identifier();
        let key = challenge.key_authorization().dns_value();
        let retry = match server.set_auth(domain, key).await {
            Ok(v) => v,
            Err(e) => return Err(erdp::wrap("couldn't set key authorization", e).into()),
        };

        // Start.
        if let Err(e) = challenge.set_ready().await {
            return Err(erdp::wrap("couldn't start the challenge", e).into());
        }

        Ok(retry)
    }

    async fn run_http(
        tasks: TaskTracker,
        http: TcpListener,
        hyper: hyper::server::conn::http1::Builder,
        challenges: Rc<HttpChallenges>,
        running: CancellationToken,
    ) {
        let hyper = Rc::new(hyper);
        let mut exit = pin!(running.cancelled());

        loop {
            // Wait for challenges.
            select! {
                biased;
                _ = &mut exit => break,
                _ = challenges.wait() => ()
            }

            // Accept connection.
            let (sock, addr) = select! {
                biased;
                _ = &mut exit => break,
                v = http.accept() => match v {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to accept HTTP connection: {}.", e.display());
                        continue;
                    },
                }
            };

            tasks.spawn_local(Self::dispatch_http(
                sock,
                addr,
                hyper.clone(),
                challenges.clone(),
                running.clone(),
            ));

            yield_now().await;
        }
    }

    async fn dispatch_http(
        sock: TcpStream,
        addr: SocketAddr,
        hyper: Rc<hyper::server::conn::http1::Builder>,
        challenges: Rc<HttpChallenges>,
        running: CancellationToken,
    ) {
        let service = hyper::service::service_fn({
            let challenges = challenges.clone();

            move |r| Self::dispatch_acme(challenges.clone(), r)
        });

        if let Err(e) = sock.set_nodelay(true) {
            eprintln!("Failed to enable TCP_NODELAY: {}.", e.display());
        }

        // Run the connection.
        let mut f = pin!(hyper.serve_connection(TokioIo::new(sock), service));
        let r = select! {
            biased;
            _ = running.cancelled() => {
                f.as_mut().graceful_shutdown();
                None
            }
            v = &mut f => Some(v),
        };

        // Check result.
        let r = match r {
            Some(v) => v,
            None => f.await,
        };

        if let Err(e) = r {
            eprintln!("Failed to serve http from {}: {}.", addr, e.display());
        }
    }

    async fn dispatch_acme(
        challenges: Rc<HttpChallenges>,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // Check method.
        let mut resp = Response::new(Full::new(Bytes::new()));

        if req.method() != Method::GET {
            *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;

            resp.headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET"));

            return Ok(resp);
        }

        // Get challenge.
        match challenges.remove(req.uri().path()) {
            Some(k) => *resp.body_mut() = Full::new(Bytes::copy_from_slice(k.as_str().as_bytes())),
            None => *resp.status_mut() = StatusCode::NOT_FOUND,
        }

        Ok(resp)
    }
}

/// Contains data required for ACME challenge.
enum Challenge {
    Http01(Rc<HttpChallenges>),
    Dns01(DnsServer),
}

/// Encapsulates DNS client.
enum DnsServer {
    Aws(Route53),
}

/// Provides method to update DNS record.
trait Dns01 {
    type Err: std::error::Error + 'static;

    fn set_auth(
        self,
        domain: &AuthorizedIdentifier,
        data: String,
    ) -> impl Future<Output = Result<RetryPolicy, Self::Err>>;
}

/// Error of [Acme::new()].
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("couldn't create account builder")]
    CreateAccountBuilder(#[source] instant_acme::Error),

    #[error("couldn't read credentials from {0}")]
    ReadCredentials(PathBuf, #[source] std::io::Error),

    #[error("couldn't load credentials from {0}")]
    LoadCredentials(PathBuf, #[source] minicbor_serde::error::DecodeError),

    #[error("couldn't load account from {0}")]
    LoadAccount(PathBuf, #[source] instant_acme::Error),

    #[error("couldn't create account")]
    CreateAccount(#[source] instant_acme::Error),

    #[error("couldn't save credentials to {0}")]
    SaveCredentials(PathBuf, #[source] std::io::Error),

    #[error("couldn't create HTTP server on {0}")]
    CreateHttpServer(SocketAddr, #[source] std::io::Error),
}

/// Error of [Acme::order()].
#[derive(Debug, Error)]
pub enum OrderError {
    #[error("couldn't create order")]
    CreateOrder(#[source] instant_acme::Error),

    #[error("couldn't retrieve authorization")]
    RetrieveAuth(#[source] instant_acme::Error),

    #[error("couldn't complete {0} challenge")]
    Challenge(&'static str, #[source] Box<dyn std::error::Error>),

    #[error("couldn't retrieve order status")]
    RetrieveOrderStatus(#[source] instant_acme::Error),

    #[error("unexpected order status {0:?}")]
    UnexpectedOrderStatus(OrderStatus),

    #[error("couldn't retrieve private key")]
    RetrievePrivateKey(#[source] instant_acme::Error),

    #[error("couldn't retrieve certificate")]
    RetrieveCert(#[source] instant_acme::Error),
}
