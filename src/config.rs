use configuration::{Config as Configuration, ConfigError};
use serde::Deserialize;
use serde_with::serde_as;
use std::{net::SocketAddr, num::NonZeroU8, ops::Deref, path::PathBuf, sync::Arc};
use time::Duration;

use crate::puzzle::Verifier;

/// Configuration of Comproxity.
#[derive(Deserialize)]
struct RawConfig {
    /// Address to which the proxy should bind such as `127.0.0.1:8000`.
    #[serde(default = "defaults::address")]
    address: SocketAddr,

    /// Endpoint calls to which should be proxied such as `http://127.0.0.1:4321`.
    endpoint: String,

    /// Key to be used for generating tokens and nonces.
    /// Any string.
    key: String,

    /// Properties of a nonce.
    nonce: NonceProperties,

    /// Path to HTML files drawn by comproxity.
    #[serde(default = "defaults::pages")]
    pages: Pages,
}

#[serde_as]
#[derive(Deserialize)]
pub struct NonceProperties {
    pub prefix_length: NonZeroU8,
    pub suffix_length: NonZeroU8,
    pub hash_suffix_length: NonZeroU8,
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub nonce_ttl: Duration,
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub token_ttl: Duration,
}

#[derive(Deserialize)]
pub struct Pages {
    #[serde(default = "defaults::pages::nonce")]
    pub nonce: PathBuf,

    #[serde(default = "defaults::pages::internal_error")]
    pub internal_error: PathBuf,
}

pub struct RuntimeConfig {
    pub address: SocketAddr,
    pub endpoint: String,
    pub verifier: Verifier,
    pub pages: Pages,
}

#[derive(Clone)]
pub struct Config(Arc<RuntimeConfig>);

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config: RawConfig = Configuration::builder()
            .add_source(configuration::File::with_name("config"))
            .add_source(configuration::Environment::with_prefix("COMPROXITY"))
            .build()
            .and_then(Configuration::try_deserialize)?;
        Ok(Self(Arc::new(RuntimeConfig {
            address: config.address,
            endpoint: config.endpoint,
            verifier: Verifier::new(config.key, config.nonce),
            pages: config.pages,
        })))
    }
}

impl Deref for Config {
    type Target = RuntimeConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

mod defaults {
    use super::Pages;
    use std::net::SocketAddr;

    pub fn address() -> SocketAddr {
        ([127, 0, 0, 1], 8000).into()
    }

    pub fn pages() -> Pages {
        Pages {
            nonce: pages::nonce(),
            internal_error: pages::internal_error(),
        }
    }

    pub mod pages {
        use std::path::PathBuf;

        pub fn nonce() -> PathBuf {
            "./assets/nonce.html".into()
        }

        pub fn internal_error() -> PathBuf {
            "./assets/internal-error.html".into()
        }
    }
}
