//! Implementation of the reverse proxy.
use crate::{
    puzzle::{AnswerError, NewNonceError},
    Config,
};
use hyper::header::HeaderName;
use hyper::http::HeaderValue;
use hyper::{header::SET_COOKIE, Body, HeaderMap, Request, Response};
use hyper_reverse_proxy::ProxyError;
use std::convert::Infallible;
use std::net::IpAddr;
use tracing::{debug, error, info, trace};
use ulid::Ulid;

pub async fn handle_request(
    config: Config,
    client_address: IpAddr,
    request: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    Ok(
        handle_unique_request(config, client_address, request, Ulid::new())
            .await
            // TODO: find a way to response with error
            .unwrap_or_else(|_error| Response::new(Body::empty())),
    )
}

#[tracing::instrument(name = "request", skip(config, request), fields(id = %id))]
async fn handle_unique_request(
    config: Config,
    client_address: IpAddr,
    request: Request<Body>,
    id: Ulid,
) -> Result<Response<Body>, hyper::http::Error> {
    use headers::{Cookie, HeaderMapExt};

    info!("Handling {request:?}");

    // clone is required since they may be re-used when handling errors
    // while the original request is passed to other methods
    let headers = request.headers().clone();
    let cookie = headers.typed_get::<Cookie>();

    let response = if let Some(cookie) = cookie {
        debug!("User has provided token");
        if let Some(token) = cookie.get(cookie_names::TOKEN) {
            match config.verifier.verify_token(&client_address, token) {
                Ok(()) => {
                    debug!("Token is valid, handling normal proxy request");
                    proxy_request(&config, client_address, request, None).await
                }
                Err(token_error) => {
                    debug!("Token is invalid {token_error}, creating a new nonce");
                    create_nonce(&config, client_address, request).await
                }
            }
        } else {
            match (
                cookie.get(cookie_names::NONCE),
                cookie.get(cookie_names::ANSWER),
            ) {
                (Some(nonce), Some(answer)) => {
                    debug!("User has provided nonce and answer, verifying it");
                    verify_answer(&config, client_address, request, nonce, answer).await
                }
                (Some(_nonce), _no_answer) => {
                    debug!("User has provided nonce without a token, requesting retry");
                    draw_nonce_page(&config, request, None).await
                }
                (_no_nonce, Some(_answer)) => {
                    debug!("User has provided answer without a nonce, giving him a new nonce");
                    create_nonce(&config, client_address, request).await
                }
                (None, None) => {
                    debug!("User has not provided anything, giving him a new nonce");
                    create_nonce(&config, client_address, request).await
                }
            }
        }
    } else {
        // since the user has not provided any cookies, so we will provide some for him
        create_nonce(&config, client_address, request).await
    };

    match response {
        Ok(response) => {
            debug!("Responding with {response:?}");
            Ok(response)
        }
        Err(error) => {
            error!("Response failed: {error}");
            match error {
                Error::Http(error) => Err(error),
                Error::ServeStaticFile(_) | Error::CreateNonce(_) | Error::Proxy(_) => {
                    match hyper_static::serve::static_file(
                        &config.pages.internal_error,
                        Some("text/html"),
                        &headers,
                        65536,
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(error) => error.into(),
                    }
                }
            }
        }
    }
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

#[tracing::instrument(skip_all)]
async fn proxy_request(
    config: &Config,
    client_address: IpAddr,
    request: Request<Body>,
    extra_headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
) -> Result<Response<Body>, Error> {
    trace!("Proxying request");

    let mut response = hyper_reverse_proxy::call(client_address, &config.endpoint, request).await?;
    add_extra_headers(response.headers_mut(), extra_headers);

    Ok(response)
}

#[tracing::instrument(skip_all)]
async fn draw_nonce_page(
    config: &Config,
    request: Request<Body>,
    extra_headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
) -> Result<Response<Body>, Error> {
    trace!("Drawing nonce page to the user");

    let mut response = hyper_static::serve::static_file(
        &config.pages.nonce,
        Some("text/html"),
        request.headers(),
        65536,
    )
    .await??;

    add_extra_headers(response.headers_mut(), extra_headers);

    Ok(response)
}

#[tracing::instrument(skip(config, request))]
async fn create_nonce(
    config: &Config,
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

#[tracing::instrument(skip(config, client_address, request))]
async fn verify_answer(
    config: &Config,
    client_address: IpAddr,
    request: Request<Body>,
    nonce: &str,
    answer: &str,
) -> Result<Response<Body>, Error> {
    trace!("Verifying user answer");

    match config.verifier.answer(&client_address, &nonce, &answer) {
        Ok(access_token) => {
            debug!("Correct answer, granting access token");
            proxy_request(
                config,
                client_address,
                request,
                [
                    (
                        SET_COOKIE,
                        HeaderValue::from_str(
                            &format_cookie!(cookie_names::TOKEN => access_token; SameSite = Lax),
                        )
                        .unwrap(),
                    ),
                    (
                        SET_COOKIE,
                        HeaderValue::from_str(
                            &format_cookie!(cookie_names::NONCE; SameSite = Lax; Remove),
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
                ],
            )
            .await
        }
        Err(
            error @ AnswerError::InvalidJwt(..)
            | error @ AnswerError::Expired { .. }
            | error @ AnswerError::SubjectMismatch { .. }
            | error @ AnswerError::InvalidExpectedHashSuffix,
        ) => {
            debug!("User can no longer solve the nonce due an error {error}, giving new nonce");
            create_nonce(config, client_address, request).await
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
            .await
        }
    }
}

#[tracing::instrument(skip_all)]
fn add_extra_headers(
    headers: &mut HeaderMap<HeaderValue>,
    extra_headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
) {
    for (name, value) in extra_headers {
        debug!("Adding extra header {name} with value {value:?}");
        let _: bool = headers.append(name, value);
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("failed to handle HTTP request: {0}")]
    Http(#[from] hyper::http::Error),

    #[error("failed to serve static file: {0}")]
    ServeStaticFile(hyper_static::serve::ErrorKind),

    #[error("failed to generate nonce: {0}")]
    CreateNonce(#[from] NewNonceError),

    #[error("failed to handle proxy request: {0:?}")]
    Proxy(ProxyError),
}

impl From<ProxyError> for Error {
    fn from(error: ProxyError) -> Self {
        Self::Proxy(error)
    }
}

impl From<hyper_static::serve::Error> for Error {
    fn from(error: hyper_static::serve::Error) -> Self {
        Self::ServeStaticFile(error.kind())
    }
}

mod cookie_names {
    pub const TOKEN: &str = "COMPROXITY_TOKEN";
    pub const ANSWER: &str = "COMPROXITY_ANSWER";
    pub const NONCE: &str = "COMPROXITY_NONCE";
}
