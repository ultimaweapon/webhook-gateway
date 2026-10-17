use bytes::Bytes;
use clap::Parser;
use erdp::ErrorDisplay;
use futures::poll;
use http::{Request, Response};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::fs::File;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZero;
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

    // Create HTTP server.
    let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let addr = SocketAddr::new(ip, args.port.into());
    let server = match TcpListener::bind(&addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to start HTTP server on {}: {}.", addr, e.display());
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

    // Load TLS certificate.
    let crt = PathBuf::from_iter(["etc", "webhook-gateway", "tls-crt.pem"]);
    let key = PathBuf::from_iter(["etc", "webhook-gateway", "tls-key.pem"]);
    let tls = match (File::open(crt.as_path()), File::open(key.as_path())) {
        (Ok(c), Ok(k)) => match load_tls(c, k) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "Failed to build TLS acceptor from {} and {}: {}.",
                    crt.display(),
                    key.display(),
                    e.display()
                );

                return ExitCode::FAILURE;
            }
        },
        (Ok(_), Err(e)) => {
            eprintln!("Failed to open {}: {}.", key.display(), e.display());
            return ExitCode::FAILURE;
        }
        (Err(e), Ok(_)) => {
            eprintln!("Failed to open {}: {}.", crt.display(), e.display());
            return ExitCode::FAILURE;
        }
        (Err(c), Err(k)) => match (c.kind(), k.kind()) {
            (ErrorKind::NotFound, ErrorKind::NotFound) => todo!(),
            _ => {
                eprintln!("Failed to open {}: {}.", crt.display(), c.display());
                return ExitCode::FAILURE;
            }
        },
    };

    drop(key);
    drop(crt);

    // Configure HTTP server.
    let http = hyper::server::conn::http1::Builder::new();

    println!("Listening for webhooks on {addr}.");

    // Construct global states.
    let app = Rc::new(App {
        running: CancellationToken::new(),
    });

    // Dispatch events.
    let http = Rc::new(http);
    let tasks = TaskTracker::new();
    let exit = loop {
        select! {
            biased;
            v = &mut exit => break v,
            v = server.accept() => match v {
                Ok((sock, addr)) => drop(tasks.spawn_local(app.clone().dispatch_http(sock, addr, tls.clone(), http.clone()))),
                Err(e) => eprintln!("Failed to accept HTTP connection: {}.", e.display()),
            }
        }

        yield_now().await;
    };

    app.running.cancel();

    drop(server);
    drop(http);
    drop(tls);
    drop(app);

    println!("Waiting for {} tasks to shutdown.", tasks.len());

    tasks.close();
    tasks.wait().await;

    exit
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
    async fn dispatch_http(
        self: Rc<Self>,
        sock: TcpStream,
        addr: SocketAddr,
        tls: TlsAcceptor,
        http: Rc<hyper::server::conn::http1::Builder>,
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
        let mut f = pin!(http.serve_connection(TokioIo::new(sock), service));
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
            eprintln!("Failed to serve http from {}: {}.", addr, e.display());
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

    /// Email address to create Let's Encrypt account.
    #[arg(value_name = "EMAIL")]
    contact: Box<str>,

    /// Port to listen for webhooks.
    port: NonZero<u16>,
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
