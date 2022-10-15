use hyper::server::conn::AddrStream;
use std::{convert::Infallible, process::ExitCode};
use tracing::{error, info};

mod config;
mod proxy;

use config::Config;

#[tokio::main]
#[tracing::instrument(name = "bootstrap")]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();

    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            error!("failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let server = hyper::Server::bind(&config.address)
        .serve(hyper::service::make_service_fn(
            move |connection: &AddrStream| {
                let client_address = connection.remote_addr();
                let config = config.clone();
                async move {
                    Ok::<_, Infallible>(hyper::service::service_fn(move |request| {
                        let config = config.clone();
                        proxy::handle_request(config, client_address, request)
                    }))
                }
            },
        ))
        .with_graceful_shutdown(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                error!("Failed to handle CTRL-C signal: {error}");
            }
            info!("Shutting down");
        });

    info!("Starting");

    if let Err(error) = server.await {
        error!("Server failed: {error}");
        return ExitCode::FAILURE;
    };

    ExitCode::SUCCESS
}
