mod proxy;

use config::Config;
use hyper::server::conn::AddrStream;
use serde::Deserialize;
use std::error::Error;
use std::{convert::Infallible, net::SocketAddr};

/// Configuration of Comproxity.
#[derive(Deserialize)]
struct ComproxityConfig {
    /// Address to which the proxy should bind such as `127.0.0.1:8000`.
    #[serde(default = "default_address")]
    address: SocketAddr,

    /// Endpoint calls to which should be proxied such as `http://127.0.0.1:4321`.
    endpoint: String,
}

fn default_address() -> SocketAddr {
    ([127, 0, 0, 1], 8000).into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config: ComproxityConfig = Config::builder()
        .add_source(config::File::with_name("config"))
        .add_source(config::Environment::with_prefix("COMPROXITY"))
        .build()?
        .try_deserialize()?;

    // TODO: find a more elegant solution to share endpoint
    let endpoint: &'static str = Box::leak(config.endpoint.clone().into_boxed_str());

    let server = hyper::Server::bind(&config.address)
        .serve(hyper::service::make_service_fn(
            move |connection: &AddrStream| {
                let client_address = connection.remote_addr();
                async move {
                    Ok::<_, Infallible>(hyper::service::service_fn(move |request| {
                        proxy::handle_request(endpoint, client_address, request)
                    }))
                }
            },
        ))
        .with_graceful_shutdown(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!("Failed to handle CTRL-C signal: {error}");
            }
            tracing::info!("Shutting down");
        });

    tracing::info!("Starting");

    server.await?;

    Ok(())
}
