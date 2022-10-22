use hyper::server::conn::AddrStream;
use std::process::ExitCode;
use tracing::{error, info};

mod config;
mod puzzle;
mod server;

use config::Config;
use server::Error as ProxyError;

#[tokio::main]
#[tracing::instrument(name = "bootstrap")]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();

    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => {
            error!("failed to load config: {error}");
            return ExitCode::FAILURE;
        }
    };

    let server = hyper::Server::bind(&config.address)
        .serve(hyper::service::make_service_fn(
            move |connection: &AddrStream| {
                let client_address = connection.remote_addr();
                let config = config.clone();
                async move {
                    Ok::<_, ProxyError>(hyper::service::service_fn(move |request| {
                        let config = config.clone();
                        server::handle_request(config, client_address, request)
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
