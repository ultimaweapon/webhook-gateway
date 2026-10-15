use erdp::ErrorDisplay;
use std::process::ExitCode;

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
    ExitCode::SUCCESS
}
