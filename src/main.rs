use bytes::Bytes;
use clap::Parser;
use erdp::ErrorDisplay;
use futures::poll;
use http::header::ALLOW;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use instant_acme::{AuthorizationStatus, ChallengeType, KeyAuthorization, OrderStatus};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::fs::File;
use std::io::{ErrorKind, Seek, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::pin;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::yield_now;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[cfg(unix)]
mod unix;

fn main() -> ExitCode {
    let args = Args::parse();
    let tokio = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build_local(Default::default())
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to build Tokio runtime: {}.", e.display());
            return ExitCode::FAILURE;
        }
    };

    tokio.block_on(run(args))
}

async fn run(args: Args) -> ExitCode {
    // Register SIGINT handler to prevent non-graceful shutdown after this.
    let mut exit = pin!(async move {
        match tokio::signal::ctrl_c().await {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Failed to wait for SIGINT: {}.", e.display());
                ExitCode::FAILURE
            }
        }
    });

    if let Poll::Ready(v) = poll!(exit.as_mut()) {
        return v;
    }

    // Create HTTP server for ACME challenge.
    let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let addr = SocketAddr::new(ip, 80);
    let http = match TcpListener::bind(&addr).await {
        Ok(v) => Rc::new(v),
        Err(e) => {
            eprintln!("Failed to start HTTP server on {}: {}.", addr, e.display());
            return ExitCode::FAILURE;
        }
    };

    // Create HTTPS server.
    let addr = SocketAddr::new(ip, 443);
    let https = match TcpListener::bind(&addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to start HTTPS server on {}: {}.", addr, e.display());
            return ExitCode::FAILURE;
        }
    };

    // Drop privilege.
    #[cfg(unix)]
    if let Some(gid) = &args.gid {
        let gid = match gid.resolve() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to resolve group {}: {}.", gid, e.display());
                return ExitCode::FAILURE;
            }
        };

        if unsafe { libc::setgroups(0, [].as_ptr()) < 0 } {
            let e = std::io::Error::last_os_error();

            eprintln!("Failed to drop supplementary groups: {}.", e.display());

            return ExitCode::FAILURE;
        }

        if unsafe { libc::setgid(gid) < 0 } {
            let e = std::io::Error::last_os_error();

            eprintln!("Failed to change GID to {}: {}.", gid, e.display());

            return ExitCode::FAILURE;
        }
    }

    #[cfg(unix)]
    if let Some(uid) = &args.uid {
        let uid = match uid.resolve() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to resolve user {}: {}.", uid, e.display());
                return ExitCode::FAILURE;
            }
        };

        if unsafe { libc::setuid(uid) < 0 } {
            let e = std::io::Error::last_os_error();

            eprintln!("Failed to change UID to {}: {}.", uid, e.display());

            return ExitCode::FAILURE;
        }
    }

    // Configure HTTP server.
    let hyper = hyper::server::conn::http1::Builder::new();

    // Create ACME account builder.
    let acme = match instant_acme::Account::builder() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to create ACME account builder: {}.", e.display());
            return ExitCode::FAILURE;
        }
    };

    // Load ACME credential.
    let path = PathBuf::from_iter(["etc", "webhook-gateway", "acme-credentials.bin"]);
    let acme = match std::fs::read(path.as_path()) {
        Ok(v) => match minicbor_serde::from_slice(&v) {
            Ok(v) => match acme.from_credentials(v).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "Failed to create ACME account from {}: {}.",
                        path.display(),
                        e.display()
                    );

                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("Failed to load {}: {}.", path.display(), e.display());
                return ExitCode::FAILURE;
            }
        },
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!("Creating a new ACME account");

            // Build request.
            let contact = format!("mailto:{}", args.contact);
            let req = instant_acme::NewAccount {
                contact: &[contact.as_str()],
                terms_of_service_agreed: args.accept_letsencrypt_tos,
                only_return_existing: false,
            };

            // Create.
            let url = "https://acme-v02.api.letsencrypt.org/directory";
            let (acc, cred) = match acme.create(&req, url.into(), None).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to create ACME account: {}.", e.display());
                    return ExitCode::FAILURE;
                }
            };

            // Save credentials.
            let cred = minicbor_serde::to_vec(cred).unwrap();

            if let Err(e) = std::fs::write(path.as_path(), cred) {
                eprintln!(
                    "Failed to save ACME credentials to {}: {}.",
                    path.display(),
                    e.display()
                );

                return ExitCode::FAILURE;
            }

            acc
        }
        Err(e) => {
            eprintln!("Failed to read {}: {}.", path.display(), e.display());
            return ExitCode::FAILURE;
        }
    };

    drop(path);

    // Open TLS certificate.
    let hyper = Rc::new(hyper);
    let cp = PathBuf::from_iter(["etc", "webhook-gateway", "tls-crt.pem"]);
    let kp = PathBuf::from_iter(["etc", "webhook-gateway", "tls-key.pem"]);
    let (crt, key) = match (File::open(cp.as_path()), File::open(kp.as_path())) {
        (Ok(c), Ok(k)) => (c, k),
        (Ok(_), Err(e)) => {
            eprintln!("Failed to open {}: {}.", kp.display(), e.display());
            return ExitCode::FAILURE;
        }
        (Err(e), Ok(_)) => {
            eprintln!("Failed to open {}: {}.", cp.display(), e.display());
            return ExitCode::FAILURE;
        }
        (Err(c), Err(k)) => match (c.kind(), k.kind()) {
            (ErrorKind::NotFound, ErrorKind::NotFound) => {
                println!("Requesting new certificate.");

                // Create file for certificate now to see it we can write it.
                let mut crt = match File::options()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(cp.as_path())
                {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to create {}: {}.", cp.display(), e.display());
                        return ExitCode::FAILURE;
                    }
                };

                // Create file for private key now to see it we can write it.
                let mut key = match File::options()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(kp.as_path())
                {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to create {}: {}.", kp.display(), e.display());
                        return ExitCode::FAILURE;
                    }
                };

                // Create ACME order.
                let domain = args.domain.as_ref().to_owned();
                let ids = [instant_acme::Identifier::Dns(domain)];
                let order = instant_acme::NewOrder::new(&ids);
                let mut order = match acme.new_order(&order).await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "Failed to create ACME order for {}: {}.",
                            args.domain,
                            e.display()
                        );

                        return ExitCode::FAILURE;
                    }
                };

                // Authorize.
                let mut auths = order.authorizations();

                while let Some(auth) = auths.next().await {
                    let mut auth = match auth {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "Failed to retrieve ACME authorization for {}: {}.",
                                args.domain,
                                e.display()
                            );

                            return ExitCode::FAILURE;
                        }
                    };

                    if auth.status != AuthorizationStatus::Pending {
                        continue;
                    }

                    // Get HTTP-01 challenge.
                    let mut challenge = match auth.challenge(ChallengeType::Http01) {
                        Some(v) => v,
                        None => {
                            eprintln!("No HTTP-01 challenge for {}.", args.domain);
                            return ExitCode::FAILURE;
                        }
                    };

                    // Start HTTP server.
                    let running = CancellationToken::new();
                    let http = tokio::task::spawn_local(run_http(
                        http.clone(),
                        hyper.clone(),
                        format!("/.well-known/acme-challenge/{}", challenge.token).into(),
                        challenge.key_authorization().into(),
                        running.clone(),
                    ));

                    // Start challenge.
                    if let Err(e) = challenge.set_ready().await {
                        eprintln!(
                            "Failed to start HTTP-01 challenge for {}: {}.",
                            args.domain,
                            e.display()
                        );

                        running.cancel();
                        http.await.unwrap();

                        return ExitCode::FAILURE;
                    }

                    drop(auths);

                    // Wait for ready.
                    let r = order.poll_ready(&Default::default()).await;

                    running.cancel();
                    http.await.unwrap();

                    match r {
                        Ok(OrderStatus::Ready) => (),
                        Ok(v) => {
                            eprintln!("Unexpected ACME order status {:?} for {}.", v, args.domain,);
                            return ExitCode::FAILURE;
                        }
                        Err(e) => {
                            eprintln!(
                                "Failed to poll for ACME order status for {}: {}.",
                                args.domain,
                                e.display()
                            );

                            return ExitCode::FAILURE;
                        }
                    }

                    break;
                }

                // Get private key.
                let v = match order.finalize().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "Failed to get private key for {}: {}.",
                            args.domain,
                            e.display()
                        );

                        return ExitCode::FAILURE;
                    }
                };

                if let Err(e) = key.write_all(v.as_bytes()) {
                    eprintln!("Failed to write {}: {}.", kp.display(), e.display());
                    return ExitCode::FAILURE;
                } else if let Err(e) = key.rewind() {
                    eprintln!("Failed to seek {}: {}.", kp.display(), e.display());
                    return ExitCode::FAILURE;
                }

                // Get certificate.
                let v = match order.poll_certificate(&Default::default()).await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "Failed to get certificate for {}: {}.",
                            args.domain,
                            e.display()
                        );

                        return ExitCode::FAILURE;
                    }
                };

                if let Err(e) = crt.write_all(v.as_bytes()) {
                    eprintln!("Failed to write {}: {}.", cp.display(), e.display());
                    return ExitCode::FAILURE;
                } else if let Err(e) = crt.rewind() {
                    eprintln!("Failed to seek {}: {}.", cp.display(), e.display());
                    return ExitCode::FAILURE;
                }

                (crt, key)
            }
            _ => {
                eprintln!("Failed to open {}: {}.", cp.display(), c.display());
                return ExitCode::FAILURE;
            }
        },
    };

    // Load TLS certificate.
    let tls = match load_tls(crt, key) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Failed to build TLS acceptor from {} and {}: {}.",
                cp.display(),
                kp.display(),
                e.display()
            );

            return ExitCode::FAILURE;
        }
    };

    drop(kp);
    drop(cp);

    // Construct global states.
    let app = Rc::new(App {
        running: CancellationToken::new(),
    });

    println!("Listening for webhooks on {addr}.");

    // Dispatch events.
    let tasks = TaskTracker::new();
    let exit = loop {
        select! {
            biased;
            v = &mut exit => break v,
            v = https.accept() => match v {
                Ok((sock, addr)) => drop(tasks.spawn_local(app.clone().dispatch_https(sock, addr, tls.clone(), hyper.clone()))),
                Err(e) => eprintln!("Failed to accept HTTPS connection: {}.", e.display()),
            }
        }

        yield_now().await;
    };

    app.running.cancel();

    drop(http);
    drop(https);
    drop(hyper);
    drop(tls);
    drop(app);

    println!("Waiting for {} tasks to shutdown.", tasks.len());

    tasks.close();
    tasks.wait().await;

    exit
}

async fn run_http(
    http: Rc<TcpListener>,
    hyper: Rc<hyper::server::conn::http1::Builder>,
    path: Rc<str>,
    body: Rc<KeyAuthorization>,
    running: CancellationToken,
) {
    let mut exit = pin!(running.cancelled());
    let tasks = TaskTracker::new();

    loop {
        let (sock, addr) = select! {
            biased;
            _ = &mut exit => break,
            v = http.accept() => match v {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to accept HTTPS connection: {}.", e.display());
                    continue;
                },
            }
        };

        tasks.spawn_local(dispatch_http(
            sock,
            addr,
            hyper.clone(),
            path.clone(),
            body.clone(),
            running.clone(),
        ));

        yield_now().await;
    }

    tasks.close();
    tasks.wait().await;
}

async fn dispatch_http(
    sock: TcpStream,
    addr: SocketAddr,
    hyper: Rc<hyper::server::conn::http1::Builder>,
    path: Rc<str>,
    body: Rc<KeyAuthorization>,
    running: CancellationToken,
) {
    let service = hyper::service::service_fn({
        let path = path.clone();
        let body = body.clone();

        move |r| dispatch_acme(path.clone(), body.clone(), r)
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
    path: Rc<str>,
    body: Rc<KeyAuthorization>,
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

    // Check path.
    if req.uri().path() != path.as_ref() {
        *resp.status_mut() = StatusCode::NOT_FOUND;

        return Ok(resp);
    }

    *resp.body_mut() = Full::new(Bytes::copy_from_slice(body.as_str().as_bytes()));

    Ok(resp)
}

fn load_tls(crt: File, key: File) -> Result<TlsAcceptor, TlsError> {
    // Load certificate.
    let mut chain = Vec::new();

    for (i, crt) in CertificateDer::pem_reader_iter(crt).enumerate() {
        match crt {
            Ok(v) => chain.push(v),
            Err(e) => return Err(TlsError::LoadCert(i, e)),
        }
    }

    // Load private key.
    let key = PrivateKeyDer::from_pem_reader(key).map_err(TlsError::LoadKey)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(TlsError::BuildAcceptor)?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config).into())
}

/// Global states for the program.
struct App {
    running: CancellationToken,
}

impl App {
    async fn dispatch_https(
        self: Rc<Self>,
        sock: TcpStream,
        addr: SocketAddr,
        tls: TlsAcceptor,
        hyper: Rc<hyper::server::conn::http1::Builder>,
    ) {
        let mut running = pin!(self.running.cancelled());
        let service = hyper::service::service_fn({
            let app = self.clone();

            move |r| app.clone().dispatch_webhook(r)
        });

        if let Err(e) = sock.set_nodelay(true) {
            eprintln!("Failed to enable TCP_NODELAY: {}.", e.display());
        }

        // Establish TLS.
        let sock = select! {
            biased;
            _ = &mut running => return,
            v = tls.accept(sock) => match v {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "Failed to establish TLS connection with {}: {}.",
                        addr,
                        e.display()
                    );

                    return;
                },
            }
        };

        // Run the connection.
        let mut f = pin!(hyper.serve_connection(TokioIo::new(sock), service));
        let r = select! {
            biased;
            _ = running => {
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
            eprintln!("Failed to serve https from {}: {}.", addr, e.display());
        }
    }

    async fn dispatch_webhook(
        self: Rc<Self>,
        _: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        Ok(Response::new(Full::new(Bytes::new())))
    }
}

#[derive(Parser)]
struct Args {
    /// User to drop privileges to.
    #[cfg(unix)]
    #[arg(long)]
    uid: Option<self::unix::Uid>,

    /// Group to drop privileges to.
    #[cfg(unix)]
    #[arg(long)]
    gid: Option<self::unix::Gid>,

    /// Accept ToS of https://acme-v02.api.letsencrypt.org/directory.
    #[arg(long)]
    accept_letsencrypt_tos: bool,

    /// Domain name to connect to this machine from Let's Encrypt.
    #[arg(value_name = "FQDN")]
    domain: Box<str>,

    /// Email address to create Let's Encrypt account.
    #[arg(value_name = "EMAIL")]
    contact: Box<str>,
}

/// Error of [App::load_tls()].
#[derive(Debug, Error)]
enum TlsError {
    #[error("couldn't load certificate #{0}")]
    LoadCert(usize, #[source] rustls::pki_types::pem::Error),

    #[error("couldn't load private key")]
    LoadKey(#[source] rustls::pki_types::pem::Error),

    #[error(transparent)]
    BuildAcceptor(rustls::Error),
}
