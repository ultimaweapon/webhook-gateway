use self::acme::Acme;
use self::config::Config;
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

mod acme;
mod config;
#[cfg(unix)]
mod unix;

fn main() -> ExitCode {
    // Open configuration.
    let args = Args::parse();
    let path = PathBuf::from_iter(["etc", "webhook-gateway", "config.json"]);
    let config = match File::open(path.as_path()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to open {}: {}.", path.display(), e.display());
            return ExitCode::FAILURE;
        }
    };

    // Load configuration.
    let config = match serde_json::from_reader(config) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to load {}: {}.", path.display(), e.display());
            return ExitCode::FAILURE;
        }
    };

    drop(path);

    // Run.
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

    tokio.block_on(async move {
        let tasks = TaskTracker::new();
        let running = CancellationToken::new();
        let r = run(args, Rc::new(config), &tasks, &running).await;

        running.cancel();

        println!("Waiting for {} tasks to shutdown.", tasks.len());

        tasks.close();
        tasks.wait().await;

        r
    })
}

async fn run(
    args: Args,
    config: Rc<Config>,
    tasks: &TaskTracker,
    running: &CancellationToken,
) -> ExitCode {
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

    // Create HTTPS server.
    let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let addr = SocketAddr::new(ip, 443);
    let https = match TcpListener::bind(&addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to start HTTPS server on {}: {}.", addr, e.display());
            return ExitCode::FAILURE;
        }
    };

    // Create ACME service before dropping privilege since it might need to bind HTTP port.
    let acme = match Acme::new(&config.acme, tasks, running).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to create ACME service: {}", e.display());
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
                println!(
                    "Requesting new certificate from {}.",
                    config.acme.directory_url
                );

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

                // Request certificate.
                let r = match acme.order(&config.acme.domain).await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!(
                            "Failed to request certificate for {}: {}.",
                            config.acme.domain,
                            e.display()
                        );

                        return ExitCode::FAILURE;
                    }
                };

                if let Err(e) = key.write_all(r.1.as_bytes()) {
                    eprintln!("Failed to write {}: {}.", kp.display(), e.display());
                    return ExitCode::FAILURE;
                } else if let Err(e) = key.rewind() {
                    eprintln!("Failed to seek {}: {}.", kp.display(), e.display());
                    return ExitCode::FAILURE;
                }

                if let Err(e) = crt.write_all(r.0.as_bytes()) {
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

    // Dispatch events.
    println!("Listening for webhooks on {addr}.");

    loop {
        select! {
            biased;
            v = &mut exit => break v,
            v = https.accept() => match v {
                Ok((sock, addr)) => drop(tasks.spawn_local(dispatch_https(sock, addr, tls.clone(), hyper.clone(), running.clone()))),
                Err(e) => eprintln!("Failed to accept HTTPS connection: {}.", e.display()),
            }
        }

        yield_now().await;
    }
}

async fn dispatch_https(
    sock: TcpStream,
    addr: SocketAddr,
    tls: TlsAcceptor,
    hyper: Rc<hyper::server::conn::http1::Builder>,
    running: CancellationToken,
) {
    let mut running = pin!(running.cancelled());
    let service = hyper::service::service_fn(dispatch_webhook);

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
    _: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::new())))
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
}

/// Error of [load_tls()].
#[derive(Debug, Error)]
enum TlsError {
    #[error("couldn't load certificate #{0}")]
    LoadCert(usize, #[source] rustls::pki_types::pem::Error),

    #[error("couldn't load private key")]
    LoadKey(#[source] rustls::pki_types::pem::Error),

    #[error(transparent)]
    BuildAcceptor(rustls::Error),
}
