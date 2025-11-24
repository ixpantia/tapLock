use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
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

use crate::error::TapLockError;
use crate::jwks::JwksClient;
use crate::{OAuth2Client, OAuth2Response};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct KeycloakTokenResponseExtra {
    id_token: String,
}

impl oauth2::ExtraTokenFields for KeycloakTokenResponseExtra {}

type KeycloakClientFull = Client<
    BasicErrorResponse,
    StandardTokenResponse<KeycloakTokenResponseExtra, BasicTokenType>,
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
pub struct KeycloakOAuth2Client {
    reqwest_client: reqwest::Client,
    client: KeycloakClientFull,
    client_id: String,
    jwks_client: JwksClient,
    use_refresh_token: bool,
}

impl KeycloakOAuth2Client {
    fn get_jwk(&self, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
        self.jwks_client.get_key(kid)
    }
}

fn decode_access_token(
    client: &KeycloakOAuth2Client,
    access_token: String,
) -> Result<OAuth2Response, TapLockError> {
    let token_trim = access_token.trim_start_matches("Bearer").trim();
    let jwt_header = decode_header(token_trim)?;
    let kid = jwt_header.kid.ok_or(TapLockError::KidNotFound)?;
    let algo = jwt_header.alg;
    let decoding_key = client.get_jwk(&kid).ok_or(TapLockError::KidNotFound)?;
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
    client: &KeycloakOAuth2Client,
    access_token: String,
) -> Result<OAuth2Response, TapLockError> {
    let token_trim = access_token.trim_start_matches("Bearer").trim();
    let jwt_header = decode_header(token_trim)?;
    let kid = jwt_header.kid.ok_or(TapLockError::KidNotFound)?;

    let decoding_key = client.jwks_client.get_key_with_refresh(&kid).await?;
    let algo = jwt_header.alg;
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

pub async fn build_oauth2_state_keycloak(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    base_url: &str,
    realm: &str,
    use_refresh_token: bool,
) -> std::result::Result<KeycloakOAuth2Client, TapLockError> {
    let base_url = base_url.trim_end_matches('/');
    let auth_url = format!("{base_url}/realms/{realm}/protocol/openid-connect/auth");
    let token_url = format!("{base_url}/realms/{realm}/protocol/openid-connect/token");
    let jwks_url = format!("{base_url}/realms/{realm}/protocol/openid-connect/certs");
    let app_url = app_url.trim_end_matches('/');
    let redirect_url = format!("{app_url}/login");

    let client = Client::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_auth_uri(AuthUrl::new(auth_url)?)
        .set_token_uri(TokenUrl::new(token_url)?)
        .set_redirect_uri(RedirectUrl::new(redirect_url)?);

    let reqwest_client = reqwest::Client::new();

    let jwks_client = JwksClient::new(jwks_url, reqwest_client.clone()).await?;

    Ok(KeycloakOAuth2Client {
        reqwest_client,
        client,
        jwks_client,
        client_id: client_id.to_string(),
        use_refresh_token,
    })
}

#[async_trait::async_trait]
impl OAuth2Client for KeycloakOAuth2Client {
    async fn exchange_refresh_token(
        &self,
        refresh_token: String,
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        if !self.use_refresh_token {
            return Err(TapLockError::new("Refresh token is disabled"));
        }
        let token_result = self
            .client
            .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token.to_string()))
            .add_scopes(
                ["openid", "email", "profile", "offline_access"].map(|s| Scope::new(s.into())),
            )
            .request_async(&self.reqwest_client)
            .await?;

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
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(&self.reqwest_client)
            .await?;

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
    ) -> std::result::Result<OAuth2Response, TapLockError> {
        let response = decode_access_token(self, access_token)?;
        Ok(response)
    }
    fn get_authorization_url(&self) -> String {
        let (auth_url, _csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent")
            .add_scopes(
                ["openid", "email", "profile", "offline_access"].map(|s| Scope::new(s.into())),
            )
            .url();
        auth_url.to_string()
    }
}
