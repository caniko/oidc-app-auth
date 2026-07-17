//! Small, provider-neutral OIDC and browser-session primitives for server apps.
//!
//! Applications own persistence and product roles.  This crate owns the
//! security-sensitive protocol mechanics shared by the applications.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
    core::{CoreClient, CoreGenderClaim, CoreProviderMetadata, CoreResponseType},
    reqwest as oidc_reqwest,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

type ConfiguredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

const DEFAULT_FLOW_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("invalid OIDC configuration: {0}")]
    Configuration(String),
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("OIDC authorization response is invalid: {0}")]
    Callback(String),
    #[error("OIDC token exchange failed: {0}")]
    Exchange(String),
    #[error("OIDC identity is not usable: {0}")]
    Identity(String),
    #[error("invalid login transaction")]
    InvalidTransaction,
    #[error("login transaction expired")]
    ExpiredTransaction,
}

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LoginTransaction {
    pub pkce_verifier: String,
    pub csrf_state: String,
    pub nonce: String,
    pub issued_at: u64,
    pub return_to: Option<String>,
}

impl LoginTransaction {
    pub fn is_expired_at(&self, now: u64) -> bool {
        now < self.issued_at || now.saturating_sub(self.issued_at) > DEFAULT_FLOW_TTL.as_secs()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Callback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: BTreeSet<String>,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub url: String,
    pub transaction: LoginTransaction,
}

pub struct OidcClient {
    metadata: CoreProviderMetadata,
    http: oidc_reqwest::Client,
    config: OidcConfig,
}

impl OidcClient {
    pub async fn discover(config: OidcConfig) -> Result<Self, AuthError> {
        if config.issuer.trim().is_empty() {
            return Err(AuthError::Configuration("issuer is empty".into()));
        }
        if config.client_id.trim().is_empty() {
            return Err(AuthError::Configuration("client_id is empty".into()));
        }
        if config.redirect_uri.trim().is_empty() {
            return Err(AuthError::Configuration("redirect_uri is empty".into()));
        }

        let http = oidc_reqwest::Client::builder()
            .redirect(oidc_reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| AuthError::Configuration(format!("HTTP client: {error}")))?;
        let issuer = IssuerUrl::new(config.issuer.clone())
            .map_err(|error| AuthError::Configuration(format!("issuer URL: {error}")))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|error| AuthError::Discovery(error.to_string()))?;
        Ok(Self {
            metadata,
            http,
            config,
        })
    }

    fn client(&self) -> Result<ConfiguredClient, AuthError> {
        let redirect = RedirectUrl::new(self.config.redirect_uri.clone())
            .map_err(|error| AuthError::Configuration(format!("redirect URI: {error}")))?;
        Ok(CoreClient::from_provider_metadata(
            self.metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            None,
        )
        .set_redirect_uri(redirect))
    }

    pub fn authorization_request(
        &self,
        return_to: Option<String>,
    ) -> Result<AuthorizationRequest, AuthError> {
        let client = self.client()?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.config.scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, csrf, nonce) = request.set_pkce_challenge(challenge).url();
        Ok(AuthorizationRequest {
            url: url.to_string(),
            transaction: LoginTransaction {
                pkce_verifier: verifier.secret().clone(),
                csrf_state: csrf.secret().clone(),
                nonce: nonce.secret().clone(),
                issued_at: unix_time_seconds(),
                return_to,
            },
        })
    }

    pub async fn complete(
        &self,
        callback: Callback,
        transaction: LoginTransaction,
    ) -> Result<VerifiedIdentity, AuthError> {
        if transaction.is_expired_at(unix_time_seconds()) {
            return Err(AuthError::ExpiredTransaction);
        }
        if let Some(error) = callback.error {
            return Err(AuthError::Callback(format!(
                "provider returned {error}: {}",
                callback.error_description.unwrap_or_default()
            )));
        }
        let code = callback
            .code
            .ok_or_else(|| AuthError::Callback("missing code".into()))?;
        let state = callback
            .state
            .ok_or_else(|| AuthError::Callback("missing state".into()))?;
        if state != transaction.csrf_state {
            return Err(AuthError::Callback("state mismatch".into()));
        }
        let client = self.client()?;
        let exchange = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|error| AuthError::Exchange(error.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(transaction.pkce_verifier));
        let tokens = exchange
            .request_async(&self.http)
            .await
            .map_err(|error| AuthError::Exchange(error.to_string()))?;
        let id_token = tokens
            .id_token()
            .ok_or_else(|| AuthError::Identity("provider returned no ID token".into()))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(transaction.nonce))
            .map_err(|error| AuthError::Identity(format!("ID token validation: {error}")))?;
        let subject = claims.subject().as_str().to_owned();
        let userinfo = client
            .user_info(
                tokens.access_token().clone(),
                Some(claims.subject().clone()),
            )
            .map_err(|error| AuthError::Identity(format!("userinfo endpoint: {error}")))?
            .request_async::<AdditionalClaims, _, CoreGenderClaim>(&self.http)
            .await
            .map_err(|error| AuthError::Identity(format!("userinfo validation: {error}")))?;
        let groups = userinfo
            .additional_claims()
            .groups
            .iter()
            .cloned()
            .collect();
        Ok(VerifiedIdentity {
            issuer: self.config.issuer.clone(),
            subject,
            email: userinfo
                .email()
                .map(|email| email.as_str().to_ascii_lowercase()),
            display_name: userinfo.name().and_then(|name| {
                serde_json::to_value(name.get(None)?)
                    .ok()?
                    .as_str()
                    .map(str::to_owned)
            }),
            groups,
            expires_at: Some(claims.expiration().timestamp().max(0) as u64),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AdditionalClaims {
    #[serde(default)]
    groups: Vec<String>,
}
impl openidconnect::AdditionalClaims for AdditionalClaims {}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn hash(&self) -> String {
        Self::hash_value(&self.0)
    }

    #[must_use]
    pub fn hash_value(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionToken(REDACTED)")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignedFlowState(LoginTransaction);

impl SignedFlowState {
    pub fn seal(secret: &[u8], transaction: LoginTransaction) -> Result<String, AuthError> {
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&transaction).map_err(|_| AuthError::InvalidTransaction)?);
        let mut mac =
            HmacSha256::new_from_slice(secret).map_err(|_| AuthError::InvalidTransaction)?;
        mac.update(payload.as_bytes());
        Ok(format!(
            "{payload}.{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }

    pub fn open(secret: &[u8], cookie: &str) -> Option<LoginTransaction> {
        let (payload, mac_hex) = cookie.split_once('.')?;
        let provided = hex::decode(mac_hex).ok()?;
        let mut mac = HmacSha256::new_from_slice(secret).ok()?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&provided).ok()?;
        let transaction: LoginTransaction =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        (!transaction.is_expired_at(unix_time_seconds())).then_some(transaction)
    }
}

pub fn sanitize_return_to(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains("\\")
        && !value.chars().any(char::is_control)
    {
        Some(value.to_owned())
    } else {
        None
    }
}

pub fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction() -> LoginTransaction {
        LoginTransaction {
            pkce_verifier: "verifier".into(),
            csrf_state: "state".into(),
            nonce: "nonce".into(),
            issued_at: unix_time_seconds(),
            return_to: Some("/console".into()),
        }
    }

    #[test]
    fn signed_transaction_round_trips_and_tampering_fails() {
        let encoded = SignedFlowState::seal(b"test-secret", transaction()).unwrap();
        assert_eq!(
            SignedFlowState::open(b"test-secret", &encoded),
            Some(transaction())
        );
        assert!(SignedFlowState::open(b"wrong-secret", &encoded).is_none());
    }

    #[test]
    fn return_paths_are_same_origin_only() {
        assert_eq!(
            sanitize_return_to(Some("/console?tab=1")),
            Some("/console?tab=1".into())
        );
        assert_eq!(sanitize_return_to(Some("https://evil.invalid")), None);
        assert_eq!(sanitize_return_to(Some("//evil.invalid")), None);
        assert_eq!(
            sanitize_return_to(Some("/console\r\nLocation: https://evil.invalid")),
            None
        );
    }

    #[test]
    fn session_tokens_are_random_and_hashable() {
        let first = SessionToken::generate();
        let second = SessionToken::generate();
        assert_ne!(first, second);
        assert_ne!(first.as_str(), first.hash());
    }

    #[test]
    fn future_login_transactions_are_rejected() {
        let mut flow = transaction();
        flow.issued_at = unix_time_seconds() + 1;
        assert!(flow.is_expired_at(unix_time_seconds()));
    }
}
