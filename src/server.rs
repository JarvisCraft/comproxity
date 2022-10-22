//! Implementation of the reverse proxy.
use crate::puzzle::{AnswerError, NewNonceError};
use crate::Config;
use hyper::header::SET_COOKIE;
use hyper::{Body, Request, Response, StatusCode};
use std::net::SocketAddr;
use tracing::{debug, error, info};
use ulid::Ulid;

pub async fn handle_request(
    config: Config,
    client_address: SocketAddr,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    handle_unique_request(config, client_address, request, Ulid::new()).await
}

#[tracing::instrument(name = "request", skip(config, request), fields(id = %id))]
async fn handle_unique_request(
    config: Config,
    client_address: SocketAddr,
    request: Request<Body>,
    id: Ulid,
) -> Result<Response<Body>, Error> {
    use headers::{Cookie, HeaderMapExt};

    info!("Handling {request:?}");

    let cookie = request.headers().typed_get::<Cookie>();

    let response = if let Some(cookie) = cookie {
        if let Some(token) = cookie.get(cookie_names::TOKEN) {
            match config.verifier.verify_token(&client_address, token) {
                Ok(()) => proxy_request(config, client_address, request).await,
                Err(_token_error) => create_nonce(config, client_address).await,
            }
        } else {
            if let (Some(nonce), Some(answer)) = (
                cookie.get(cookie_names::NONCE),
                cookie.get(cookie_names::ANSWER),
            ) {
                verify_answer(config, client_address, nonce, answer).await
            } else {
                create_nonce(config, client_address).await
            }
        }
    } else {
        create_nonce(config, client_address).await
    };
    match &response {
        Ok(response) => debug!("Responding with {response:?}"),
        Err(error) => error!("Failed to response: {error}"),
    }

    response
}

macro_rules! format_cookie {
    ($key:expr => $value:expr; SameSite=Lax) => {{
        format!("{}={}; path=/; SameSite=Lax", $key, $value)
    }};
    ($key:expr; SameSite=Lax; Remove) => {{
        format!(
            "{}=; path=/; SameSite=Lax; expires=Thu, 01 Jan 1970 00:00:00 GMT",
            $key
        )
    }};
}

#[tracing::instrument(skip(config, request))]
async fn proxy_request(
    config: Config,
    client_address: SocketAddr,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    match hyper_reverse_proxy::call(client_address.ip(), &config.endpoint, request).await {
        Ok(response) => Ok(response),
        Err(error) => {
            error!("Failed to handle proxy request: {error:?}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!(
                    "Request failed due to an internal error"
                )))?)
        }
    }
}

#[tracing::instrument(skip(config))]
async fn create_nonce(config: Config, client_address: SocketAddr) -> Result<Response<Body>, Error> {
    let nonce = config
        .verifier
        .new_nonce(client_address)
        .expect("Failed to create nonce");

    Ok(Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(
            SET_COOKIE,
            format_cookie!(cookie_names::NONCE => nonce; SameSite = Lax),
        )
        .body(Body::from(format!(
            "Please, make sure to complete the task: {nonce}",
        )))?)
}

#[tracing::instrument(skip(config))]
async fn verify_answer(
    config: Config,
    client_address: SocketAddr,
    nonce: &str,
    answer: &str,
) -> Result<Response<Body>, Error> {
    Ok(
        match config.verifier.answer(&client_address, &nonce, &answer) {
            Ok(access_token) => Response::builder()
                .status(StatusCode::OK)
                .header(
                    SET_COOKIE,
                    format_cookie!(cookie_names::TOKEN => access_token; SameSite = Lax),
                )
                .header(
                    SET_COOKIE,
                    format_cookie!(cookie_names::NONCE; SameSite = Lax; Remove),
                )
                .body(Body::from(
                    "Successfully validated cookie, now try reconnecting",
                ))?,
            Err(
                AnswerError::InvalidJwt(_)
                | AnswerError::Expired
                | AnswerError::InvalidSubject
                | AnswerError::InvalidExpectedHashSuffix,
            ) => create_nonce(config, client_address).await?,
            Err(AnswerError::WrongAnswer) => Response::builder()
                .status(StatusCode::PRECONDITION_FAILED)
                .body(Body::from(format!("Wrong answer, try again")))?,
        },
    )
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to handle HTTP request: {0}")]
    HttpError(#[from] hyper::http::Error),

    #[error("failed to generate nonce: {0}")]
    NonceCreationError(#[from] NewNonceError),
}

mod cookie_names {
    pub const TOKEN: &'static str = "COMPROXITY_TOKEN";
    pub const ANSWER: &'static str = "COMPROXITY_ANSWER";
    pub const NONCE: &'static str = "COMPROXITY_NONCE";
}
