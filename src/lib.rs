//! Small, provider-neutral OIDC and browser-session primitives for server apps.
//!
//! Applications own persistence and product roles.  This crate owns the
//! security-sensitive protocol mechanics shared by the applications.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use rand::{RngCore, rngs::OsRng};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_FLOW_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The local OIDC configuration is incomplete or malformed.
    #[error("invalid OIDC configuration: {0}")]
    Configuration(String),
    /// Provider metadata discovery failed.
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    /// The callback was missing required values or failed state validation.
    #[error("OIDC authorization response is invalid: {0}")]
    Callback(String),
    /// The authorization code could not be exchanged for tokens.
    #[error("OIDC token exchange failed: {0}")]
    Exchange(String),
    /// The provider returned an identity that could not be verified or used.
    #[error("OIDC identity is not usable: {0}")]
    Identity(String),
    /// The signed flow state could not be encoded or authenticated.
    #[error("invalid login transaction")]
    InvalidTransaction,
    /// The login transaction is older than the bounded flow lifetime.
    #[error("login transaction expired")]
    ExpiredTransaction,
}

/// Public OIDC client settings for a browser authorization-code flow.
///
/// This crate intentionally models a public client: no client secret is
/// accepted or stored. Applications should keep any provider-specific secret
/// handling outside this type.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    /// The issuer URL used for bounded provider metadata discovery.
    pub issuer: String,
    /// The public OAuth/OIDC client identifier.
    pub client_id: String,
    /// The callback URL registered for this client.
    pub redirect_uri: String,
    /// Scopes requested during authorization.
    pub scopes: Vec<String>,
}

/// State retained between authorization and callback handling.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LoginTransaction {
    /// The PKCE verifier paired with the authorization request.
    pub pkce_verifier: String,
    /// The CSRF state value returned by the provider.
    pub csrf_state: String,
    /// The nonce used to validate the ID token.
    pub nonce: String,
    /// Unix timestamp at which the transaction was issued.
    pub issued_at: u64,
    /// An optional same-origin path to use after successful login.
    pub return_to: Option<String>,
}

impl LoginTransaction {
    /// Returns whether the transaction is before `now` or outside its bounded
    /// ten-minute lifetime.
    pub fn is_expired_at(&self, now: u64) -> bool {
        now < self.issued_at || now.saturating_sub(self.issued_at) > DEFAULT_FLOW_TTL.as_secs()
    }
}

/// Values received from an OIDC authorization callback.
#[derive(Clone, Debug, Deserialize)]
pub struct Callback {
    /// The authorization code, when the provider completed the request.
    pub code: Option<String>,
    /// The CSRF state returned by the provider.
    pub state: Option<String>,
    /// A provider-reported OAuth error, when authorization failed.
    pub error: Option<String>,
    /// An optional human-readable description of `error`.
    pub error_description: Option<String>,
}

/// Verified identity claims returned by [`OidcClient::complete`].
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedIdentity {
    /// The issuer that authenticated the subject.
    pub issuer: String,
    /// The provider-stable subject identifier.
    pub subject: String,
    /// A normalized lower-case email address, when supplied by the provider.
    pub email: Option<String>,
    /// A display name, when supplied by the provider.
    pub display_name: Option<String>,
    /// Group claims supplied by the provider.
    pub groups: BTreeSet<String>,
    /// The ID token expiry as a Unix timestamp, when available.
    pub expires_at: Option<u64>,
}

/// The authorization URL and state that must be retained for its callback.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    /// The provider authorization URL.
    pub url: String,
    /// The state needed to validate and complete the callback.
    pub transaction: LoginTransaction,
}

/// The provider metadata this crate uses, from the discovery document.
#[derive(Clone, Debug, Deserialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    Many(Vec<String>),
    One(serde::de::IgnoredAny),
}

#[derive(Debug, Deserialize)]
struct IdClaims {
    sub: String,
    aud: Audience,
    azp: Option<String>,
    exp: u64,
    iat: Option<u64>,
    nonce: Option<String>,
    at_hash: Option<String>,
}

#[derive(Default, Deserialize)]
struct UserInfo {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

/// Clock skew tolerated for `exp`, `nbf` and `iat`.
const LEEWAY_SECS: u64 = 60;

/// ID-token signature algorithms accepted. `none` and `HS*` are never allowed.
const ALLOWED_ALGS: [Algorithm; 3] = [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA];

/// A discovered OIDC provider client using public-client PKCE.
pub struct OidcClient {
    metadata: ProviderMetadata,
    http: reqwest::Client,
    config: OidcConfig,
}

impl OidcClient {
    /// Discover provider metadata and construct a bounded HTTP client.
    ///
    /// Returns [`AuthError::Configuration`] for invalid local settings and
    /// [`AuthError::Discovery`] when the issuer cannot be discovered.
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
        Url::parse(&config.redirect_uri)
            .map_err(|error| AuthError::Configuration(format!("redirect URI: {error}")))?;
        Url::parse(&config.issuer)
            .map_err(|error| AuthError::Configuration(format!("issuer URL: {error}")))?;

        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| AuthError::Configuration(format!("HTTP client: {error}")))?;
        let url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let metadata: ProviderMetadata = get_json(http.get(url))
            .await
            .map_err(AuthError::Discovery)?;
        if metadata.issuer != config.issuer {
            return Err(AuthError::Discovery(format!(
                "issuer mismatch: expected {}, got {}",
                config.issuer, metadata.issuer
            )));
        }
        Ok(Self {
            metadata,
            http,
            config,
        })
    }

    /// Build an authorization URL and fresh S256 PKCE transaction.
    ///
    /// The returned transaction must be retained until [`Self::complete`] is
    /// called. `return_to` is carried as application state and should be
    /// passed through [`sanitize_return_to`] before it is supplied here.
    pub fn authorization_request(
        &self,
        return_to: Option<String>,
    ) -> Result<AuthorizationRequest, AuthError> {
        let mut url = Url::parse(&self.metadata.authorization_endpoint).map_err(|error| {
            AuthError::Configuration(format!("authorization endpoint: {error}"))
        })?;
        let verifier = random_token();
        let csrf_state = random_token();
        let nonce = random_token();
        let mut scopes = vec!["openid"];
        scopes.extend(
            self.config
                .scopes
                .iter()
                .map(String::as_str)
                .filter(|scope| *scope != "openid"),
        );
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &csrf_state)
            .append_pair("nonce", &nonce)
            .append_pair(
                "code_challenge",
                &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            )
            .append_pair("code_challenge_method", "S256");
        Ok(AuthorizationRequest {
            url: url.to_string(),
            transaction: LoginTransaction {
                pkce_verifier: verifier,
                csrf_state,
                nonce,
                issued_at: unix_time_seconds(),
                return_to,
            },
        })
    }

    /// Validate a callback, exchange its code with PKCE, and return verified
    /// identity claims.
    ///
    /// The transaction is single-use from the caller's perspective: callers
    /// should remove it from their session store after attempting completion.
    /// Errors cover expiry, callback/state mismatches, exchange failures, and
    /// invalid identity claims. This method does not panic for provider or
    /// network failures.
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
        let tokens: TokenResponse =
            get_json(self.http.post(&self.metadata.token_endpoint).form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("client_id", self.config.client_id.as_str()),
                ("code_verifier", transaction.pkce_verifier.as_str()),
            ]))
            .await
            .map_err(AuthError::Exchange)?;
        let id_token = tokens
            .id_token
            .ok_or_else(|| AuthError::Identity("provider returned no ID token".into()))?;
        let jwks: JwkSet = get_json(self.http.get(&self.metadata.jwks_uri))
            .await
            .map_err(|error| AuthError::Identity(format!("JWKS: {error}")))?;
        let claims = verify_id_token(
            &id_token,
            &jwks,
            &self.config.issuer,
            &self.config.client_id,
            &transaction.nonce,
            &tokens.access_token,
        )
        .map_err(|error| AuthError::Identity(format!("ID token validation: {error}")))?;

        let endpoint = self
            .metadata
            .userinfo_endpoint
            .as_ref()
            .ok_or_else(|| AuthError::Identity("userinfo endpoint: not advertised".into()))?;
        let userinfo: UserInfo =
            get_json(self.http.get(endpoint).bearer_auth(&tokens.access_token))
                .await
                .map_err(|error| AuthError::Identity(format!("userinfo validation: {error}")))?;
        if userinfo.sub != claims.sub {
            return Err(AuthError::Identity(
                "userinfo validation: subject mismatch".into(),
            ));
        }
        Ok(VerifiedIdentity {
            issuer: self.config.issuer.clone(),
            subject: claims.sub,
            email: userinfo.email.map(|email| email.to_ascii_lowercase()),
            display_name: userinfo.name,
            groups: userinfo.groups.into_iter().collect(),
            expires_at: Some(claims.exp),
        })
    }
}

/// Send a request and parse a successful JSON response.
async fn get_json<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
) -> Result<T, String> {
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    response.json().await.map_err(|error| error.to_string())
}

/// 256 random bits, base64url-encoded: PKCE verifier, state and nonce.
fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Verify an ID token's signature (against `jwks`, selected by `kid`) and
/// claims: allowed algorithm, `iss`, `aud`, `azp`, `exp`, `nbf`, `iat`,
/// `nonce`, and `at_hash` when present.
fn verify_id_token(
    token: &str,
    jwks: &JwkSet,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    access_token: &str,
) -> Result<IdClaims, String> {
    let header = jsonwebtoken::decode_header(token).map_err(|error| error.to_string())?;
    if !ALLOWED_ALGS.contains(&header.alg) {
        return Err(format!("algorithm {:?} not allowed", header.alg));
    }
    let jwk = match (&header.kid, jwks.keys.as_slice()) {
        (Some(kid), _) => jwks.find(kid),
        (None, [only]) => Some(only),
        _ => None,
    }
    .ok_or("no matching signing key")?;
    let key = DecodingKey::from_jwk(jwk).map_err(|error| error.to_string())?;
    let mut validation = Validation::new(header.alg);
    validation.leeway = LEEWAY_SECS;
    validation.validate_nbf = true;
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = jsonwebtoken::decode::<IdClaims>(token, &key, &validation)
        .map_err(|error| error.to_string())?
        .claims;

    if claims.nonce.as_deref() != Some(nonce) {
        return Err("nonce mismatch".into());
    }
    let multiple = matches!(&claims.aud, Audience::Many(audiences) if audiences.len() > 1);
    match claims.azp.as_deref() {
        Some(azp) if azp != client_id => return Err("azp mismatch".into()),
        None if multiple => return Err("azp missing for multiple audiences".into()),
        _ => {}
    }
    if claims
        .iat
        .is_some_and(|iat| iat > unix_time_seconds() + LEEWAY_SECS)
    {
        return Err("iat is in the future".into());
    }
    // at_hash: left half of the SHA-256 of the access token (all allowed
    // algorithms use a 256-bit hash).
    if let Some(at_hash) = &claims.at_hash {
        let digest = Sha256::digest(access_token.as_bytes());
        if *at_hash != URL_SAFE_NO_PAD.encode(&digest[..16]) {
            return Err("at_hash mismatch".into());
        }
    }
    Ok(claims)
}

#[derive(Clone, PartialEq, Eq)]
/// An opaque, randomly generated browser-session token.
pub struct SessionToken(String);

impl SessionToken {
    /// Generate a new 256-bit token encoded without padding.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Return the opaque token for setting a browser cookie or persisting it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the token for persistence without storing the bearer value.
    #[must_use]
    pub fn hash(&self) -> String {
        Self::hash_value(&self.0)
    }

    /// Hash an arbitrary token value with SHA-256.
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
/// A signed, short-lived representation of login state suitable for a cookie.
pub struct SignedFlowState(LoginTransaction);

impl SignedFlowState {
    /// Serialize and authenticate a transaction with an application secret.
    ///
    /// The returned value is opaque to the browser. A sufficiently random
    /// secret is required; callers must still enforce cookie policy and
    /// single-use semantics.
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

    /// Verify and decode a cookie, returning `None` for tampering or expiry.
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

/// Keep only same-origin absolute paths for post-login redirects.
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

/// Return the current Unix timestamp in seconds, saturating before the epoch.
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

    // Test-only RSA key (generated for this fixture; protects nothing).
    const TEST_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvMMoYHJ6xbjxFgYUc986J2j+z3gLpGykggyx1Vj8T83SolqL
U8iAXslPl5lorHTi3JAY7k3No5XGsiBT8Tayv7VeMxEcFtjJ3qIPdsebgq0V85MZ
XfM1o59MXl9CTBBkcGCY6hPXKTsgSdGsBTQds/ZXUtNZv5UM/2wGiNSDJRD4dRd3
Ukg/PRRbtVMLl6lotcuUFVBb9JYUHbPP6pQO/266VoQsM9Vg0yfaL6QkzortJVfk
3AaaV35/LrG+RZAkTMeNJ6iYqWQEguDlXqb94zefkf9y1hEz0XtxezXftGynRhZH
YcPlUQU6MlET0zEcvPu4jZHsWW10bge5cPNXTwIDAQABAoIBAAu+gq0Zgkz5+Dn8
D9qzuU0Jac0jtWm5/rQ+sPPKsQwQDLpgMsn4MBB1qveOKmaMcS7y4jI1cgVrBK1B
eKeJ1S47TQyVVG+RdmHdKGQmACVtum9oqAvh3WT8PMakW54a6Pza7bimmlzs2lHt
cyvxtaVkPsOe9bcHQYNEx9VMj4pHPCa2w4i6puXBUHSTgWgTs0JhJiYYDVR5A5Ku
6W+QnB/rcIPu72bQr5c7VPZ4aj0RshENGctZqA0jLyITKWmqCQTjRZS8ovC27ClP
TgnewC9+kkf/amRTqYRGriNP7TrIug2p+9iPjklyPBFKrKbUBzBGmxqIfh2qVId0
iF/sDWECgYEA5BicP5qtx/I9BkWNQwHsETFjaUwUR2BGPcRV51WcO/qmBhyu51jq
dHNU0X1r/ppMpSdaBZPQTfmUs0xDpS+Uh2NGQdB39FMEY7LO7HvIM2dlkgv+Pj5r
TEeg8bFACtgpiSdsIDPqsjsOCANszDbb7y36xEBtcGD7Z5GA3VVS3C8CgYEA09q2
iFTtZSda6jWLFPzCwGRknjrUNbI05njajs2If0N4KCHiXqS63lDjAAthMlKCVICC
GqWjG8EAmeyFC9FtLUmr1QY/ksRxFvz+dL9JBGriW/eZZlVITdEZukWz3+2v9pKv
tXGhJLVPF5e5nzGO1/cssMzeoNCEv15b/UKuzuECgYBJHPZgkOUpVSVocDzigKg5
rpoN83wAkQSS4e8jMtbchvBWvzT1JRQp9Zn3eHt4Zd8xhRae+Q1pIRogCs8YENNM
Pm8Tw43fvAiJKJSZSugWSgtNsBhzvTBJiCA3uLgtgbJ2qzNGcz3EmZdazDZAk0kW
NqfN5lTuE7giL4qd566iswKBgC3Hq34WbB5ZvMmzvFRSsnsEtsGCkOzxj4DmSMRn
IcHugH6bo+Ez07XK4OLXkq9fKQ69nl/Hv1F2CX05oR6GqQMKUnl8GizLCm0fSpVL
6Kltt3CMNrfoYfF+6AJaoZ4YLNgpppKc9WeLToYYoWIHQYjlvuCNxOYXaTg5WcOG
r2PBAoGAZe5mh6Z6NaFFJ8ij+xIwN6izR2tBD2gLYh5+xXd4FRpwWaxPZLn7AHEi
4ToSichsfptLkNLnmy2J4HZD+bhbnRsmyB+yael1ItudRhM0wBp4yV33pBY/Fiq8
GyIBZfMLy9B1L+2HsYLxvX7bom7CNl3VFkNuuBspm8azyzWGC+w=
-----END RSA PRIVATE KEY-----
";
    const TEST_N: &str = "vMMoYHJ6xbjxFgYUc986J2j-z3gLpGykggyx1Vj8T83SolqLU8iAXslPl5lorHTi3JAY7k3No5XGsiBT8Tayv7VeMxEcFtjJ3qIPdsebgq0V85MZXfM1o59MXl9CTBBkcGCY6hPXKTsgSdGsBTQds_ZXUtNZv5UM_2wGiNSDJRD4dRd3Ukg_PRRbtVMLl6lotcuUFVBb9JYUHbPP6pQO_266VoQsM9Vg0yfaL6QkzortJVfk3AaaV35_LrG-RZAkTMeNJ6iYqWQEguDlXqb94zefkf9y1hEz0XtxezXftGynRhZHYcPlUQU6MlET0zEcvPu4jZHsWW10bge5cPNXTw";
    const ISS: &str = "https://idp.invalid/auth/";
    const CLIENT: &str = "client";

    fn jwks() -> JwkSet {
        serde_json::from_value(serde_json::json!({"keys": [
            {"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": TEST_N, "e": "AQAB"}
        ]}))
        .unwrap()
    }

    fn claims() -> serde_json::Value {
        let now = unix_time_seconds();
        serde_json::json!({
            "iss": ISS, "sub": "u1", "aud": CLIENT, "nonce": "n1",
            "iat": now, "exp": now + 300,
        })
    }

    fn mint(kid: &str, claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    fn verify(token: &str) -> Result<IdClaims, String> {
        verify_id_token(token, &jwks(), ISS, CLIENT, "n1", "at")
    }

    #[test]
    fn valid_rs256_token_verifies() {
        assert_eq!(verify(&mint("k1", &claims())).unwrap().sub, "u1");
    }

    #[test]
    fn claim_checks_reject_bad_tokens() {
        let now = unix_time_seconds();
        let mutate = |key: &str, value: serde_json::Value| {
            let mut c = claims();
            c[key] = value;
            mint("k1", &c)
        };
        assert!(verify(&mutate("iss", "https://evil.invalid/".into())).is_err());
        assert!(verify(&mutate("aud", "other".into())).is_err());
        assert!(verify(&mutate("nonce", "n2".into())).is_err());
        assert!(verify(&mutate("exp", (now - 3600).into())).is_err());
        assert!(verify(&mutate("nbf", (now + 3600).into())).is_err());
        assert!(verify(&mutate("iat", (now + 3600).into())).is_err());
        assert!(verify(&mutate("azp", "other".into())).is_err());
        assert!(verify(&mutate("at_hash", "bad".into())).is_err());
        assert!(verify(&mutate("aud", serde_json::json!([CLIENT, "x"]))).is_err());
        let mut c = claims();
        c["aud"] = serde_json::json!([CLIENT, "x"]);
        c["azp"] = CLIENT.into();
        assert!(verify(&mint("k1", &c)).is_ok());
        let mut c = claims();
        c.as_object_mut().unwrap().remove("nonce");
        assert!(verify(&mint("k1", &c)).is_err());
    }

    #[test]
    fn unknown_kid_and_bad_signature_are_rejected() {
        assert!(verify(&mint("other", &claims())).is_err());
        let token = mint("k1", &claims());
        let (head, sig) = token.rsplit_once('.').unwrap();
        let forged = format!("{head}.{}", sig.chars().rev().collect::<String>());
        assert!(verify(&forged).is_err());
    }

    #[test]
    fn none_and_hmac_algorithms_are_rejected() {
        let b64 = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let none = format!(
            "{}.{}.",
            b64(serde_json::json!({"alg": "none", "kid": "k1"})),
            b64(claims())
        );
        assert!(verify(&none).is_err());
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.kid = Some("k1".into());
        let hs = jsonwebtoken::encode(
            &header,
            &claims(),
            &jsonwebtoken::EncodingKey::from_secret(TEST_N.as_bytes()),
        )
        .unwrap();
        assert!(verify(&hs).unwrap_err().contains("not allowed"));
    }

    #[test]
    fn authorization_url_carries_s256_pkce_state_and_nonce() {
        let client = OidcClient {
            metadata: ProviderMetadata {
                issuer: ISS.into(),
                authorization_endpoint: "https://idp.invalid/authorize".into(),
                token_endpoint: String::new(),
                jwks_uri: String::new(),
                userinfo_endpoint: None,
            },
            http: reqwest::Client::new(),
            config: OidcConfig {
                issuer: ISS.into(),
                client_id: CLIENT.into(),
                redirect_uri: "https://app.invalid/cb".into(),
                scopes: vec!["email".into()],
            },
        };
        let request = client.authorization_request(None).unwrap();
        let url = Url::parse(&request.url).unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["scope"], "openid email");
        assert_eq!(q["state"], request.transaction.csrf_state);
        assert_eq!(q["nonce"], request.transaction.nonce);
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(
            q["code_challenge"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(request.transaction.pkce_verifier.as_bytes()))
        );
    }
}
