use std::fmt::Display;
use std::net::IpAddr;

use crate::config::NonceProperties;
use compact_str::CompactString;
use hmac::Hmac;
use jwt::SignWithKey;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use smallvec::{smallvec, SmallVec};
use time::{Duration, OffsetDateTime};

/// Unique object identifying the user.
pub type ClientIdentity = IpAddr;

pub type HmacSha256 = Hmac<Sha256>;

pub struct Verifier {
    key: HmacSha256,
    nonce_properties: NonceProperties,
}

impl Verifier {
    pub fn new(key: impl AsRef<[u8]>, nonce_properties: NonceProperties) -> Self {
        use hmac::Mac;

        Self {
            key: HmacSha256::new_from_slice(key.as_ref())
                .expect("`Hmac<Sha256>` should permit any string"),
            nonce_properties,
        }
    }

    pub fn new_nonce(&self, identity: ClientIdentity) -> Result<String, NewNonceError> {
        use jwt::{header::HeaderContentType, header::HeaderType, AlgorithmType, Header, Token};

        let header = Header {
            algorithm: AlgorithmType::Hs256,
            type_: Some(HeaderType::JsonWebToken),
            content_type: Some(HeaderContentType::JsonWebToken),
            ..Default::default()
        };

        let prefix = random_compact_string(self.nonce_properties.prefix_length.get().into());
        let suffix = random_compact_string(self.nonce_properties.suffix_length.get().into());
        let hash_suffix =
            random_compact_hex_string(self.nonce_properties.hash_suffix_length.get().into());

        Ok(Token::new(
            header,
            Nonce {
                subject: identity,
                issued_at: OffsetDateTime::now_utc(),
                prefix,
                suffix,
                hash_suffix,
            },
        )
        .sign_with_key(&self.key)?
        .as_str()
        .to_string())
    }

    pub fn answer(
        &self,
        identity: &ClientIdentity,
        nonce: impl AsRef<str>,
        answer: impl AsRef<str>,
    ) -> Result<String, AnswerError> {
        use jwt::VerifyWithKey;
        use sha2::Digest;

        let nonce: Nonce = nonce.as_ref().verify_with_key(&self.key)?;
        if &nonce.subject != identity {
            return Err(AnswerError::SubjectMismatch {
                expected: *identity,
                actual: nonce.subject,
            });
        }
        if let Err(expired_at) = check_expired(nonce.issued_at, self.nonce_properties.nonce_ttl) {
            return Err(AnswerError::Expired { expired_at });
        }

        let expected_hash = compact_hex_string_to_bytes::<32>(&nonce.hash_suffix)
            .map_err(|()| AnswerError::InvalidExpectedHashSuffix)?;

        let mut hasher = Sha256::new();
        hasher.update(answer.as_ref());
        let actual_hash = hasher.finalize();

        if !actual_hash
            .iter()
            .rev()
            .take(expected_hash.len())
            .eq(expected_hash.iter().rev())
        {
            return Err(AnswerError::WrongAnswer);
        }

        Ok(AccessToken {
            subject: *identity,
            issued_at: OffsetDateTime::now_utc(),
        }
        .sign_with_key(&self.key)?
        .as_str()
        .to_string())
    }

    pub fn verify_token(
        &self,
        identity: &ClientIdentity,
        token: impl AsRef<str>,
    ) -> Result<(), VerifyTokenError> {
        use jwt::VerifyWithKey;
        let token: AccessToken = token.as_ref().verify_with_key(&self.key)?;

        if &token.subject != identity {
            return Err(VerifyTokenError::SubjectMismatch {
                expected: *identity,
                actual: token.subject,
            });
        }

        if let Err(expired_at) = check_expired(token.issued_at, self.nonce_properties.token_ttl) {
            return Err(VerifyTokenError::Expired { expired_at });
        }

        Ok(())
    }
}

fn random_compact_string(length: usize) -> CompactString {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

// TODO(CertainLach): provide a more efficient implementation
fn random_compact_hex_string(length: usize) -> CompactString {
    debug_assert!(
        length.checked_mul(2).is_some(),
        "length should not be of absurd size"
    );

    let mut buffer: SmallVec<[u8; 8]> = smallvec![0; length];
    rand::thread_rng().fill_bytes(&mut buffer);

    let mut string_buffer: SmallVec<[u8; 16]> = smallvec![0; length * 2];
    hex::encode_to_slice(&buffer, &mut string_buffer)
        .expect("buffer is exactly of the required size");

    CompactString::from_utf8(string_buffer).expect("string is guaranteed to consist of hex digits")
}

fn compact_hex_string_to_bytes<const MAX_LENGTH: usize>(
    hex_string: &CompactString,
) -> Result<SmallVec<[u8; 8]>, ()> {
    let bytes_length = hex_string.len() / 2;
    if bytes_length > MAX_LENGTH {
        return Err(());
    }

    let mut buffer = smallvec![0; bytes_length];
    hex::decode_to_slice(hex_string.as_bytes(), &mut buffer)
        .map(|()| buffer)
        .map_err(|_| ())
}

fn check_expired(time: OffsetDateTime, ttl: Duration) -> Result<(), OffsetDateTime> {
    let expiration_time = time.saturating_add(ttl);
    if expiration_time < OffsetDateTime::now_utc() {
        Err(expiration_time)
    } else {
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NewNonceError {
    /// JWT token is invalid.
    #[error("JWT token is invalid: {0}")]
    InvalidJwt(#[from] jwt::error::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum AnswerError {
    /// JWT token is invalid.
    #[error("JWT token is invalid: {0}")]
    InvalidJwt(#[from] jwt::error::Error),

    /// Token subject is invalid.
    #[error("nonce has expired at {expired_at}")]
    Expired { expired_at: OffsetDateTime },

    /// Nonce subject does not match.
    #[error("invalid nonce subject: expected {expected} but got {actual}")]
    SubjectMismatch {
        expected: ClientIdentity,
        actual: ClientIdentity,
    },

    /// Invalid expected hash suffix.
    #[error("invalid expected hash suffix")]
    InvalidExpectedHashSuffix,

    /// The answer is wrong.
    #[error("answer is wrong")]
    WrongAnswer,
}

#[derive(thiserror::Error, Debug)]
pub enum VerifyTokenError {
    /// JWT token is invalid.
    #[error("JWT token is invalid: {0}")]
    InvalidJwt(#[from] jwt::error::Error),

    /// Token has expired.
    #[error("token has expired at {expired_at}")]
    Expired { expired_at: OffsetDateTime },

    /// Wrong subject.
    #[error("invalid token subject: expected {expected} but got {actual}")]
    SubjectMismatch {
        expected: ClientIdentity,
        actual: ClientIdentity,
    },
}

/// A computationally complex task to be solved by the verified entity.
/// The entity has to find any string `x` such as:
/// ```text
/// sha256(prefix + x + suffix).ends_with(hash_suffix)
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct Nonce {
    #[serde(rename = "sub")]
    subject: ClientIdentity,
    #[serde(rename = "iat", with = "time::serde::timestamp")]
    issued_at: OffsetDateTime,
    prefix: CompactString,
    suffix: CompactString,
    hash_suffix: CompactString,
}

/// Token, providing access without a need to perform validation.
#[derive(Serialize, Deserialize)]
pub struct AccessToken {
    #[serde(rename = "sub")]
    subject: ClientIdentity,
    #[serde(rename = "iat", with = "time::serde::timestamp")]
    issued_at: OffsetDateTime,
}

impl Display for Nonce {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{{prefix = \"{}\", suffix = \"{}\", hash_suffix = \"{}\"}}",
            self.prefix, self.suffix, self.hash_suffix
        )
    }
}
