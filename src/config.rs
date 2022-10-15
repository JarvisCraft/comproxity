use configuration::{Config as Configuration, ConfigError};
use serde::Deserialize;
use std::{net::SocketAddr, ops::Deref, sync::Arc};

/// Configuration of Comproxity.
#[derive(Deserialize)]
pub(crate) struct ConfigInner {
    /// Address to which the proxy should bind such as `127.0.0.1:8000`.
    #[serde(default = "default_address")]
    pub(crate) address: SocketAddr,

    /// Endpoint calls to which should be proxied such as `http://127.0.0.1:4321`.
    pub(crate) endpoint: String,
}

fn default_address() -> SocketAddr {
    ([127, 0, 0, 1], 8000).into()
}

#[derive(Clone)]
pub(crate) struct Config(Arc<ConfigInner>);

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config: ConfigInner = Configuration::builder()
            .add_source(::configuration::File::with_name("config"))
            .add_source(::configuration::Environment::with_prefix("COMPROXITY"))
            .build()
            .and_then(Configuration::try_deserialize)?;
        Ok(Self(Arc::new(config)))
    }
}

impl Deref for Config {
    type Target = ConfigInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
