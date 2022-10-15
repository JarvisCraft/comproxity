//! Implementation of the reverse proxy.

use crate::Config;
use hyper::{Body, Request, Response, StatusCode};
use std::{convert::Infallible, net::SocketAddr};
use ulid::Ulid;

pub(crate) async fn handle_request(
    config: Config,
    client_address: SocketAddr,
    request: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    handle_unique_request(config, client_address, request, Ulid::new()).await
}

#[tracing::instrument(name = "request", skip(config, request))]
async fn handle_unique_request(
    config: Config,
    client_address: SocketAddr,
    request: Request<Body>,
    id: Ulid,
) -> Result<Response<Body>, Infallible> {
    tracing::info!("Handling {request:?}");

    match hyper_reverse_proxy::call(client_address.ip(), &config.endpoint, request).await {
        Ok(response) => {
            tracing::debug!("Responding with {response:?}");
            Ok(response)
        }
        Err(error) => {
            tracing::error!("Failed to handle request: {error:?}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!(
                    "Request {id} failed due to an internal error"
                )))
                .unwrap())
        }
    }
}
