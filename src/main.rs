use erdp::ErrorDisplay;
use futures::poll;
use std::pin::pin;
use std::process::ExitCode;
use std::task::Poll;
use tokio::select;

fn main() -> ExitCode {
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

    tokio.block_on(run())
}

async fn run() -> ExitCode {
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

    // Dispatch connections.
    let exit = loop {
        select! {
            biased;
            v = &mut exit => break v,
        }
    };

    exit
}
