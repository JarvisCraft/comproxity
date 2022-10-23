use std::fmt::Display;
use std::net::SocketAddr;

use crate::config::NonceProperties;
use compact_str::CompactString;
use hmac::Hmac;
use jwt::SignWithKey;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use smallvec::SmallVec;
use time::{Duration, OffsetDateTime};

/// Unique object identifying the user.
pub type ClientIdentity = SocketAddr;

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

        let prefix = random_compact_string(self.nonce_properties.prefix_length.get());
        let suffix = random_compact_string(self.nonce_properties.suffix_length.get());
        let hash_suffix = random_compact_hex_string(self.nonce_properties.hash_suffix_length.get());

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
            return Err(AnswerError::InvalidSubject);
        }
        if has_expired(nonce.issued_at, self.nonce_properties.nonce_ttl) {
            return Err(AnswerError::Expired);
        }

        let expected_hash = compact_hex_string_to_bytes::<32>(&nonce.hash_suffix)
            .map_err(|_| AnswerError::InvalidExpectedHashSuffix)?;

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
            return Err(VerifyTokenError::WrongSubject);
        }

        if has_expired(token.issued_at, self.nonce_properties.token_ttl) {
            return Err(VerifyTokenError::Expired);
        }

        Ok(())
    }
}

fn random_compact_string(length: impl Into<usize>) -> CompactString {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(length.into())
        .map(char::from)
        .collect()
}

// TODO(CertainLach): provide a more efficient implementation
fn random_compact_hex_string(length: impl Into<usize>) -> CompactString {
    let length = length.into();

    let mut buffer: SmallVec<[u8; 8]> = smallvec::smallvec![0; length];
    rand::thread_rng().fill_bytes(&mut buffer);

    let mut string = CompactString::with_capacity(length);
    for byte in buffer {
        const HEX_DICTIONARY: [char; 16] = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        ];

        string.push(HEX_DICTIONARY[(byte >> 4 & 0xF) as usize]);
        string.push(HEX_DICTIONARY[(byte & 0xF) as usize]);
    }

    string
}

fn compact_hex_string_to_bytes<const MAX_LENGTH: usize>(
    hex_string: &CompactString,
) -> Result<SmallVec<[u8; 8]>, ()> {
    let length = hex_string.len();
    if length % 2 == 1 {
        return Err(());
    }

    let length = length / 2;
    if length > MAX_LENGTH {
        return Err(());
    }

    let mut buffer = SmallVec::with_capacity(length / 2);

    let mut string_bytes = hex_string.bytes();
    while let Some(left_byte) = string_bytes.next() {
        fn to_byte_half(byte: u8) -> Result<u8, ()> {
            match byte {
                byte @ b'0'..=b'9' => Ok(byte - b'0'),
                byte @ b'A'..=b'F' => Ok(byte - b'A'),
                _ => Err(()),
            }
        }

        let right_byte = string_bytes
            .next()
            .expect("string is known to be of even length by now");

        buffer.push(to_byte_half(left_byte)? << 4 | to_byte_half(right_byte)?)
    }

    Ok(buffer)
}

fn has_expired(time: OffsetDateTime, ttl: Duration) -> bool {
    time.saturating_add(ttl) < OffsetDateTime::now_utc()
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

    /// Nonce subject does not match.
    #[error("invalid nonce subject")]
    InvalidSubject,

    /// Token subject is invalid.
    #[error("nonce has expired")]
    Expired,

    /// Invalid expected hash suffix.
    #[error("invalid expected hash hash")]
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
    #[error("token has expired")]
    Expired,

    /// Wrong subject.
    #[error("token subject does not match")]
    WrongSubject,
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
