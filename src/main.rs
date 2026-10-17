use bytes::Bytes;
use erdp::ErrorDisplay;
use futures::poll;
use http::{Request, Response};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::pin;
use std::process::ExitCode;
use std::rc::Rc;
use std::task::Poll;
use tokio::net::TcpStream;
use tokio::select;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

fn main() -> ExitCode {
    // Build Tokio runtime.
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

    // Run.
    let app = Rc::new(App {
        running: CancellationToken::new(),
    });

    tokio.block_on(app.run())
}

/// Global states for the program.
struct App {
    running: CancellationToken,
}

impl App {
    async fn run(self: Rc<Self>) -> ExitCode {
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

        // Dispatch events.
        let exit = loop {
            select! {
                biased;
                v = &mut exit => break v,
            }
        };

        exit
    }

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
