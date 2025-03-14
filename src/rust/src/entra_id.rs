use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use oauth2::TokenResponse;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    StandardRevocableToken, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::{Arc, Mutex};

use crate::{OAuth2Client, OAuth2Error, OAuth2Response};

const JWKS_URL: &'static str = "https://login.microsoftonline.com/common/discovery/keys";

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AzureADTokenResponseExtra {
    id_token: String,
}

impl oauth2::ExtraTokenFields for AzureADTokenResponseExtra {}

type AzureADClientFull = Client<
    BasicErrorResponse,
    StandardTokenResponse<AzureADTokenResponseExtra, BasicTokenType>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

#[derive(Clone)]
pub struct AzureADOAuth2Client {
    reqwest_client: reqwest::Client,
    client: AzureADClientFull,
    client_id: String,
    jwks: Arc<Mutex<JwkSet>>,
    use_refresh_token: bool,
    tenant_id: String, // Add tenant ID
}

impl AzureADOAuth2Client {
    fn get_jwk(&self, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
        let jwks = self.jwks.lock().expect("mutex should not be poissoned");
        jwks.find(&kid).cloned()
    }
}

async fn fetch_jwks(reqwest_client: &reqwest::Client) -> Result<JwkSet, OAuth2Error> {
    eprintln!("Refreshing JwkSet");
    let jwks = reqwest_client
        .get(JWKS_URL)
        .send()
        .await?
        .json::<JwkSet>()
        .await?;
    Ok(jwks)
}

async fn refresh_jwks(
    reqwest_client: &reqwest::Client,
    jwks_container: &Mutex<JwkSet>,
) -> Result<(), OAuth2Error> {
    let jwks = fetch_jwks(reqwest_client).await?;
    let mut jwks_container = jwks_container
        .lock()
        .expect("mutex should not be poissoned");
    *jwks_container = jwks;
    Ok(())
}

fn decode_access_token(
    client: &AzureADOAuth2Client,
    access_token: String,
) -> Result<OAuth2Response, OAuth2Error> {
    let token_trim = access_token.trim_start_matches("Bearer").trim();
    let jwt_header = decode_header(token_trim)?;
    let kid = jwt_header.kid.ok_or("Missing `kid` in token header")?;
    let algo = jwt_header.alg;
    let decoding_key = client.get_jwk(&kid).ok_or(OAuth2Error::KidNotFound)?;
    let mut validation = Validation::new(algo);

    validation.set_audience(&[&client.client_id]);

    let val = decode::<serde_json::Value>(
        token_trim,
        &DecodingKey::from_jwk(&decoding_key)?,
        &validation,
    )?;

    Ok(OAuth2Response {
        access_token,
        refresh_token: None,
        fields: val.claims,
    })
}

async fn decode_token_and_maybe_refresh_jwks(
    client: &AzureADOAuth2Client,
    access_token: String,
) -> Result<OAuth2Response, OAuth2Error> {
    let mut response = decode_access_token(client, access_token.clone());
    if let Err(OAuth2Error::KidNotFound) = response {
        refresh_jwks(&client.reqwest_client, &client.jwks).await?;
        response = decode_access_token(client, access_token.clone());
    }
    response
}

pub async fn build_oauth2_state_azure_ad(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    use_refresh_token: bool,
    tenant_id: &str, // Add tenant ID as a parameter
) -> std::result::Result<AzureADOAuth2Client, Box<dyn Error>> {
    let auth_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
        tenant_id
    );
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let redirect_url = format!("{app_url}login");

    let client = Client::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_auth_uri(AuthUrl::new(auth_url)?)
        .set_token_uri(TokenUrl::new(token_url)?)
        .set_redirect_uri(RedirectUrl::new(redirect_url)?);

    let reqwest_client = reqwest::Client::new();

    let jwks = fetch_jwks(&reqwest_client).await?;
    let jwks = Arc::new(Mutex::new(jwks));

    Ok(AzureADOAuth2Client {
        reqwest_client,
        client,
        jwks,
        client_id: client_id.to_string(),
        use_refresh_token,
        tenant_id: tenant_id.to_string(), // Store tenant ID
    })
}

#[async_trait::async_trait]
impl OAuth2Client for AzureADOAuth2Client {
    async fn exchange_refresh_token(
        &self,
        refresh_token: String,
    ) -> std::result::Result<OAuth2Response, OAuth2Error> {
        if !self.use_refresh_token {
            return Err(OAuth2Error::new("Refresh token is disabled"));
        }

        let token_result = self
            .client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token.to_string()))
            .add_scope(Scope::new(format!("{}/.default", self.client_id)))
            .add_scopes(
                ["openid", "email", "profile", "offline_access"].map(|s| Scope::new(s.into())),
            ) // Add offline_access
            .request_async(&self.reqwest_client)
            .await
            .map_err(|e| e.to_string())?;

        let access_token = token_result.extra_fields().id_token.clone();
        let mut response = decode_token_and_maybe_refresh_jwks(self, access_token).await?;
        if self.use_refresh_token {
            response.refresh_token = Some(
                token_result
                    .refresh_token()
                    .map(|rt| rt.secret().clone())
                    .unwrap_or(refresh_token),
            );
        }
        Ok(response)
    }
    async fn exchange_code(
        &self,
        code: String,
    ) -> std::result::Result<OAuth2Response, OAuth2Error> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(&self.reqwest_client)
            .await
            .map_err(|e| e.to_string())?;

        let access_token = token_result.extra_fields().id_token.clone();
        let mut response = decode_token_and_maybe_refresh_jwks(self, access_token).await?;

        if self.use_refresh_token {
            response.refresh_token = token_result.refresh_token().map(|rt| rt.secret().clone());
        }

        Ok(response)
    }
    fn decode_access_token(
        &self,
        access_token: String,
    ) -> std::result::Result<OAuth2Response, OAuth2Error> {
        let response = decode_access_token(self, access_token)?;
        Ok(response)
    }
    fn get_authorization_url(&self) -> String {
        let (auth_url, _csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(format!("{}/.default", self.client_id)))
            .add_scopes(
                ["openid", "email", "profile", "offline_access"].map(|s| Scope::new(s.into())),
            ) // Add offline_access
            .url();
        auth_url.to_string()
    }
}
