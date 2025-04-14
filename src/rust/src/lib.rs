mod cookies;
mod entra_id;
mod google;
use extendr_api::prelude::*;
use std::sync::Arc;
use tokio::sync::oneshot::{self, error::TryRecvError};

#[extendr]
enum FutureResult {
    Error(Robj),
    Ready(Robj),
    Pending,
}

#[extendr]
impl FutureResult {
    fn is_error(&self) -> bool {
        matches!(self, Self::Error(..))
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(..))
    }

    fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    fn error(&self) -> Nullable<Robj> {
        match self {
            FutureResult::Error(e) => NotNull(e.clone()),
            _ => Null,
        }
    }

    fn value(&self) -> Nullable<Robj> {
        match self {
            FutureResult::Ready(v) => NotNull(v.clone()),
            _ => Null,
        }
    }
}

#[derive(Debug)]
pub(crate) enum OAuth2Error {
    Msg(String),
    KidNotFound,
}

#[derive(Debug)]
pub(crate) struct OAuth2Response {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub fields: serde_json::Value,
}

fn from_json_value_to_robj(value: &serde_json::Value) -> Robj {
    match value {
        serde_json::Value::Null => NULL.into_robj(),
        serde_json::Value::Object(inner) => {
            let iter = inner.into_iter();
            let mut names = Vec::with_capacity(iter.len());
            let mut values = Vec::with_capacity(iter.len());
            for (key, value) in iter {
                names.push(key);
                values.push(from_json_value_to_robj(value));
            }
            let mut res = List::from_values(values);
            res.as_robj_mut()
                .set_names(names)
                .unwrap()
                .as_list()
                .unwrap()
        }
        .into_robj(),
        serde_json::Value::Bool(b) => b.into_robj(),
        serde_json::Value::Array(a) => {
            List::from_values(a.iter().map(from_json_value_to_robj)).into_robj()
        }
        serde_json::Value::Number(n) => n.as_f64().into_robj(),
        serde_json::Value::String(s) => s.into_robj(),
    }
}

impl IntoRobj for &OAuth2Response {
    fn into_robj(self) -> Robj {
        let fields = from_json_value_to_robj(&self.fields);
        list!(
            access_token = self.access_token.clone(),
            refresh_token = self.refresh_token.clone(),
            fields = fields
        )
        .into()
    }
}

impl IntoRobj for &OAuth2Error {
    fn into_robj(self) -> Robj {
        match self {
            OAuth2Error::Msg(msg) => Strings::from(&msg).into_robj(),
            OAuth2Error::KidNotFound => "KidNotFound".into_robj(),
        }
    }
}

impl OAuth2Error {
    pub(crate) fn new(msg: &str) -> Self {
        OAuth2Error::Msg(msg.to_string())
    }
}

impl std::error::Error for OAuth2Error {}
impl std::fmt::Display for OAuth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuth2Error::KidNotFound => write!(f, "KidNotFound"),
            OAuth2Error::Msg(msg) => write!(f, "OAuth2Error: {msg}"),
        }
    }
}

impl From<&str> for OAuth2Error {
    fn from(value: &str) -> Self {
        OAuth2Error::new(value)
    }
}

impl From<String> for OAuth2Error {
    fn from(msg: String) -> Self {
        OAuth2Error::Msg(msg)
    }
}

impl From<jsonwebtoken::errors::Error> for OAuth2Error {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        OAuth2Error::Msg(format!("jsonwebtoken error: {value}"))
    }
}

impl From<reqwest::Error> for OAuth2Error {
    fn from(value: reqwest::Error) -> Self {
        OAuth2Error::Msg(format!("reqwest error: {value}"))
    }
}

#[extendr]
struct AsyncFuture {
    rx: oneshot::Receiver<std::result::Result<OAuth2Response, OAuth2Error>>,
}

#[extendr]
impl AsyncFuture {
    fn poll(&mut self) -> FutureResult {
        match self.rx.try_recv() {
            Ok(Ok(robj)) => FutureResult::Ready(robj.into_robj()),
            Ok(Err(err)) => FutureResult::Error(err.into_robj()),
            Err(TryRecvError::Empty) => FutureResult::Pending,
            Err(e) => panic!("{e}"),
        }
    }
}

// We are using async_trait since older compilers do not support
// async traits natively
#[async_trait::async_trait]
pub(crate) trait OAuth2Client: Send + Sync {
    async fn exchange_refresh_token(
        &self,
        refresh_token: String,
    ) -> std::result::Result<OAuth2Response, OAuth2Error>;
    async fn exchange_code(&self, code: String)
        -> std::result::Result<OAuth2Response, OAuth2Error>;
    fn decode_access_token(
        &self,
        access_token: String,
    ) -> std::result::Result<OAuth2Response, OAuth2Error>;
    fn get_authorization_url(&self) -> String;
}

#[extendr]
struct OAuth2Runtime {
    runtime: tokio::runtime::Runtime,
    client: Arc<dyn OAuth2Client>,
    app_url: Robj,
}

#[extendr]
impl OAuth2Runtime {
    // Should return a AsyncFuture with a List containing the access_token
    // and the refresh token
    fn request_token(&self, authorization_code: String) -> AsyncFuture {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let client = Arc::clone(&self.client);
        self.runtime.spawn(async move {
            let response = client.exchange_code(authorization_code).await;
            let _ = tx.send(response);
        });
        AsyncFuture { rx }
    }

    // Should return a AsyncFuture with a List containing the new access_token
    // and the refresh token
    fn request_token_refresh(&self, refresh_token: String) -> AsyncFuture {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let client = Arc::clone(&self.client);
        self.runtime.spawn(async move {
            let response = client.exchange_refresh_token(refresh_token).await;
            let _ = tx.send(response);
        });
        AsyncFuture { rx }
    }

    // Should return a list with the deocoded token in the form of a list
    // or an error if the token is invalid
    fn decode_token(&self, token: String) -> Result<Robj> {
        let res = self
            .client
            .decode_access_token(token)
            .map_err(|_| Error::from("Hello".to_string()))?;
        Ok(res.into_robj())
    }

    fn get_authorization_url(&self) -> String {
        self.client.get_authorization_url()
    }

    fn get_app_url(&self) -> Robj {
        self.app_url.clone()
    }
}

#[extendr]
fn initialize_google_runtime(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    use_refresh_token: bool,
) -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    let client = runtime.block_on(google::build_oauth2_state_google(
        client_id,
        client_secret,
        app_url,
        use_refresh_token,
    ))?;

    let client = Arc::from(client);

    let app_url = Strings::from(app_url).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

#[extendr]
fn initialize_entra_id_runtime(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    tenant_id: &str,
    use_refresh_token: bool,
) -> Result<OAuth2Runtime> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    let client = runtime.block_on(entra_id::build_oauth2_state_azure_ad(
        client_id,
        client_secret,
        app_url,
        use_refresh_token,
        tenant_id,
    ))?;

    let client = Arc::from(client);

    let app_url = Strings::from(app_url).into_robj();

    Ok(OAuth2Runtime {
        client,
        runtime,
        app_url,
    })
}

/// Return string `"Hello world!"` to R.
/// @export
#[extendr]
fn hello_world() -> &'static str {
    "Hello world!"
}

// Macro to generate exports.
// This ensures exported functions are registered with R.
// See corresponding C code in `entrypoint.c`.
extendr_module! {
    mod tapLock;
    use cookies;
    fn hello_world;
    fn initialize_google_runtime;
    fn initialize_entra_id_runtime;
    impl AsyncFuture;
    impl FutureResult;
    impl OAuth2Runtime;
}
