use extendr_api::IntoRobj;
use oauth2::{url, ErrorResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TapLockError {
    #[error("TapLock error: {0}")]
    Msg(String),
    #[error("URL Parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("OAuth2 configuration error: {0}")]
    OAuth2Config(#[from] oauth2::ConfigurationError),
    #[error("HTTP request error: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Request Token error: {0}")]
    RequestToken(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON Web Token error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("KID not found in JWKs")]
    KidNotFound,
}

impl TapLockError {
    pub fn new(msg: impl Into<String>) -> Self {
        TapLockError::Msg(msg.into())
    }
}

impl<TE, TR> From<oauth2::RequestTokenError<TE, TR>> for TapLockError
where
    TE: std::error::Error + 'static,
    TR: ErrorResponse + 'static,
{
    fn from(value: oauth2::RequestTokenError<TE, TR>) -> Self {
        TapLockError::RequestToken(value.to_string())
    }
}

impl From<TapLockError> for extendr_api::Error {
    fn from(err: TapLockError) -> Self {
        err.to_string().into()
    }
}

impl IntoRobj for TapLockError {
    fn into_robj(self) -> extendr_api::Robj {
        extendr_api::Strings::from(self.to_string()).into_robj()
    }
}
