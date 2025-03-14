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

use crate::{OAuth2Client, OAuth2Error, OAuth2Response};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct GoogleTokenResponseExtra {
    id_token: String,
}

impl oauth2::ExtraTokenFields for GoogleTokenResponseExtra {}

pub type GoogleClientFull = Client<
    BasicErrorResponse,
    StandardTokenResponse<GoogleTokenResponseExtra, BasicTokenType>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct GoogleTokenFields {
    email: String,
}

#[derive(Clone)]
pub struct GoogleOAuth2Client {
    reqwest_client: reqwest::Client,
    client: GoogleClientFull,
    client_id: String,
    jwks: JwkSet,
    use_refresh_token: bool,
}

pub async fn build_oauth2_state_google(
    client_id: &str,
    client_secret: &str,
    app_url: &str,
    use_refresh_token: bool,
) -> std::result::Result<GoogleOAuth2Client, Box<dyn Error>> {
    let auth_url = "https://accounts.google.com/o/oauth2/v2/auth";
    let token_url = "https://oauth2.googleapis.com/token";
    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    let redirect_url = format!("{app_url}login");

    let client = Client::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_auth_uri(AuthUrl::new(auth_url.to_string())?)
        .set_token_uri(TokenUrl::new(token_url.to_string())?)
        .set_redirect_uri(RedirectUrl::new(redirect_url)?);

    let reqwest_client = reqwest::Client::new();

    let jwks = reqwest_client
        .get(jwks_url)
        .send()
        .await?
        .json::<JwkSet>()
        .await?;

    Ok(GoogleOAuth2Client {
        reqwest_client,
        client,
        jwks,
        client_id: client_id.to_string(),
        use_refresh_token,
    })
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
}

fn decode_access_token(
    client: &GoogleOAuth2Client,
    access_token: String,
) -> Result<OAuth2Response, OAuth2Error> {
    let token_trim = access_token.trim_start_matches("Bearer").trim();
    let jwt_header = decode_header(token_trim)?;
    let kid = jwt_header.kid.ok_or("Missing `kid` in token header")?;
    let algo = jwt_header.alg;
    let decoding_key = client.jwks.find(&kid).ok_or("Key ID not found in JWKS")?;
    let mut validation = Validation::new(algo);
    validation.set_audience(&[&client.client_id]);
    let val = decode::<serde_json::Value>(
        token_trim,
        &DecodingKey::from_jwk(decoding_key)?,
        &validation,
    )?;

    Ok(OAuth2Response {
        access_token,
        refresh_token: None,
        fields: val.claims,
    })
}

#[async_trait::async_trait]
impl OAuth2Client for GoogleOAuth2Client {
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
            .add_scopes(["openid", "email", "profile"].map(|s| Scope::new(s.into())))
            .request_async(&self.reqwest_client)
            .await
            .map_err(|e| e.to_string())?;

        let access_token = token_result.extra_fields().id_token.clone();
        let mut response = decode_access_token(self, access_token.clone())?;
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
        let mut response = decode_access_token(self, access_token)?;

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
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent")
            .add_scopes(["openid", "email", "profile"].map(|s| Scope::new(s.into())))
            .url();
        auth_url.to_string()
    }
}
