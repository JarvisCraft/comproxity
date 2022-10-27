//! Implementation of the reverse proxy.
use crate::{
    puzzle::{AnswerError, NewNonceError},
    Config,
};
use hyper::header::HeaderName;
use hyper::http::HeaderValue;
use hyper::{header::SET_COOKIE, Body, Request, Response, StatusCode};
use std::net::IpAddr;
use tracing::{debug, error, info, trace};
use ulid::Ulid;

pub async fn handle_request(
    config: Config,
    client_address: IpAddr,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    handle_unique_request(config, client_address, request, Ulid::new()).await
}

#[tracing::instrument(name = "request", skip(config, request), fields(id = %id))]
async fn handle_unique_request(
    config: Config,
    client_address: IpAddr,
    request: Request<Body>,
    id: Ulid,
) -> Result<Response<Body>, Error> {
    use headers::{Cookie, HeaderMapExt};

    info!("Handling {request:?}");

    let cookie = request.headers().typed_get::<Cookie>();

    let response = if let Some(cookie) = cookie {
        debug!("User has provided token");
        if let Some(token) = cookie.get(cookie_names::TOKEN) {
            match config.verifier.verify_token(&client_address, token) {
                Ok(()) => {
                    debug!("Token is valid, handling normal proxy request");
                    proxy_request(config, client_address, request).await
                }
                Err(token_error) => {
                    debug!("Token is invalid {token_error}, creating a new nonce");
                    create_nonce(config, client_address, request).await
                }
            }
        } else {
            match (
                cookie.get(cookie_names::NONCE),
                cookie.get(cookie_names::ANSWER),
            ) {
                (Some(nonce), Some(answer)) => {
                    debug!("User has provided nonce and answer, verifying it");
                    verify_answer(config, client_address, request, nonce, answer).await
                }
                (Some(_nonce), _answer @ None) => {
                    debug!("User has provided nonce without a token, requesting retry");
                    draw_nonce_page(config, request, None).await
                }
                (_nonce @ None, Some(_answer)) => {
                    debug!("User has provided answer without a nonce, giving him a new nonce");
                    create_nonce(config, client_address, request).await
                }
                (None, None) => {
                    debug!("User has not provided anything, giving him a new nonce");
                    create_nonce(config, client_address, request).await
                }
            }
        }
    } else {
        // since the user has not provided any cookies, so we will provide some for him
        create_nonce(config, client_address, request).await
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
    client_address: IpAddr,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    trace!("Proxying request");

    match hyper_reverse_proxy::call(client_address, &config.endpoint, request).await {
        Ok(response) => Ok(response),
        Err(error) => {
            error!("Failed to handle proxy request: {error:?}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Request failed due to an internal error"))?)
        }
    }
}

#[tracing::instrument(skip(config, request, extra_headers))]
async fn draw_nonce_page(
    config: Config,
    request: Request<Body>,
    extra_headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
) -> Result<Response<Body>, Error> {
    trace!("Drawing nonce page to the user");

    let mut response = hyper_static::serve::static_file(
        &config.nonce_page,
        Some("text/html"),
        &request.headers(),
        65536,
    )
    .await
    .map_err(|file_error| {
        error!("Failed to load static file {file_error}");
        Error::InternalError
    })??;

    let headers = response.headers_mut();
    for (name, value) in extra_headers {
        debug!("Overriding header {name} with value {value:?}");
        let _: bool = headers.append(name, value);
    }

    Ok(response)
}

#[tracing::instrument(skip(config, request))]
async fn create_nonce(
    config: Config,
    client_address: IpAddr,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    trace!("Creating new nonce for the user");

    let nonce = config
        .verifier
        .new_nonce(client_address)
        .expect("Failed to create nonce");

    draw_nonce_page(
        config,
        request,
        [
            (
                SET_COOKIE,
                HeaderValue::from_str(
                    &format_cookie!(cookie_names::NONCE => nonce; SameSite = Lax),
                )
                .unwrap(),
            ),
            (
                SET_COOKIE,
                HeaderValue::from_str(
                    &format_cookie!(cookie_names::ANSWER; SameSite = Lax; Remove),
                )
                .unwrap(),
            ),
            (
                SET_COOKIE,
                HeaderValue::from_str(&format_cookie!(cookie_names::TOKEN; SameSite = Lax; Remove))
                    .unwrap(),
            ),
        ],
    )
    .await
}

#[tracing::instrument(skip(config, request))]
async fn verify_answer(
    config: Config,
    client_address: IpAddr,
    request: Request<Body>,
    nonce: &str,
    answer: &str,
) -> Result<Response<Body>, Error> {
    trace!("Verifying user answer");

    Ok(
        match config.verifier.answer(&client_address, &nonce, &answer) {
            Ok(access_token) => {
                debug!("Correct answer, granting access token");
                Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        SET_COOKIE,
                        format_cookie!(cookie_names::TOKEN => access_token; SameSite = Lax),
                    )
                    .header(
                        SET_COOKIE,
                        format_cookie!(cookie_names::NONCE; SameSite = Lax; Remove),
                    )
                    .header(
                        SET_COOKIE,
                        format_cookie!(cookie_names::ANSWER; SameSite = Lax; Remove),
                    )
                    .body(Body::from(
                        "Successfully validated cookie, now try reconnecting",
                    ))?
            }
            Err(
                error @ AnswerError::InvalidJwt(..)
                | error @ AnswerError::Expired
                | error @ AnswerError::InvalidSubject(..)
                | error @ AnswerError::InvalidExpectedHashSuffix,
            ) => {
                debug!("User can no longer solve the nonce due an error {error}, giving new nonce");
                create_nonce(config, client_address, request).await?
            }
            Err(AnswerError::WrongAnswer) => {
                debug!("User has answered wrongly, forcing him to retry");
                draw_nonce_page(
                    config,
                    request,
                    Some((
                        SET_COOKIE,
                        HeaderValue::from_str(
                            &format_cookie!(cookie_names::ANSWER; SameSite=Lax; Remove),
                        )
                        .unwrap(),
                    )),
                )
                .await?
            }
        },
    )
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to handle HTTP request: {0}")]
    HyperHttpError(#[from] hyper::http::Error),

    #[error("failed to generate nonce: {0}")]
    NonceCreationError(#[from] NewNonceError),

    #[error("something went wrong")]
    InternalError,
}

mod cookie_names {
    pub const TOKEN: &str = "COMPROXITY_TOKEN";
    pub const ANSWER: &str = "COMPROXITY_ANSWER";
    pub const NONCE: &str = "COMPROXITY_NONCE";
}
