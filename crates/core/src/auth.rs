//! Federated sign-in: provider identities linked to own-domain mailboxes.
//!
//! ayane is the first consumer of the family's login contract. The pieces
//! it composes, none of them written here:
//!
//! * [`kirino::auth::mode::LoginPolicy`] — the discovery document every
//!   login panel in the family renders from (`GET /api/auth/login-methods`
//!   and the `session.loginPolicy` RPC answer the same value);
//! * [`kirino::auth::passport::oauth`] — the relying-party protocol core
//!   (PKCE, the one-time `state`, the token exchange, the identity read).
//!   This module never builds a token request: it parks attempts, binds
//!   them to the browser and hands the callback to `finish`;
//! * [`kirino::auth::identity::external::ExternalIdentityStore`] — the link
//!   model, implemented here over the snapshot store ([`IdentityLinks`]).
//!
//! # What a provider sign-in means here (2026-11-24 rulings)
//!
//! A provider proves **who** the visitor is; it never says anything about
//! a mailbox. The linked mailbox is an own-domain account whose password
//! the server keeps only as a hash, so the SPA asks for that password once
//! on the verify card — exactly today's password login, kept for the
//! session only ([`crate::session::Session::needs_mailbox_password`]).
//! A Dovecot master-user proxy (a genuinely password-less read) is a later
//! upgrade and is NOT implemented; [`ayane_store::StoredState::cached_credential`]
//! is the single hook it, or a cached forwarding-node account, plugs into.
//!
//! The first sign-in through a provider only reaches an **existing**
//! mailbox: an identity nobody linked is refused (`oauth_error=unlinked`).
//! Linking happens from an authenticated session (`/account`), never as a
//! self-service mailbox request.
//!
//! # Browser flow
//!
//! ```text
//! SPA  session.oauthBegin {provider, returnTo?}  ──► ticket (one-time, 10 min) — a SIGN-IN, always
//! SPA  session.linkIdentity {provider}           ──► the same ticket — to LINK, authenticated alone
//! GET  /api/auth/oauth/{provider}?ticket=…       ──► Set-Cookie binding; 302 authorize
//!                                                 (spent here, on its own provider's route only)
//! GET  /api/auth/oauth/{provider}/callback?code&state
//!                                                 ──► finish(…) → identity
//!      linked   → handoff code → 302 {base}/login?handoff=…
//!      unlinked →               302 {base}/login?oauth_error=unlinked
//!      link purpose → link() →  302 {base}/account?linked={provider}
//! SPA  session.claimHandoff {code} ──► session (+ needs_mailbox_password)
//! ```
//!
//! The purpose is the METHOD's and nothing else's: `session.oauthBegin`
//! is a sign-in whatever token the connection holds (it reads none), and
//! linking goes only through `session.linkIdentity`. A sign-in that
//! reaches an existing mailbox mints a session that is **locked** until
//! the mailbox password is proven once: the provider said who the visitor
//! is, and that password is the account's second factor for the mailbox
//! and for every privileged surface alike ([`crate::rpc`]).
//!
//! The binding cookie (`ayane_oauth_binding`, HttpOnly, `SameSite=Lax`,
//! scoped to `/api/auth/oauth`) closes login CSRF: a callback that reaches
//! this service from another browser than the one that started the attempt
//! is refused. No token, code or secret ever rides a URL: the handoff is a
//! one-time code and every failure names a reason from a closed list.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use async_trait::async_trait;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use ayane_proto::Address;
use ayane_store::{ExternalLink, StateStore, StoredState};
use chrono::{Duration as ChronoDuration, Utc};
use kirino::auth::identity::external::{
    ExternalIdentity, ExternalIdentityStore, LinkOutcome, LinkedAccount,
};
use kirino::auth::mode::{AuthMode, LoginMethodDescriptor, LoginPolicy, LOGIN_POLICY_VERSION};
use kirino::auth::passport::oauth::{
    authorize_url, begin_with_binding, finish, Callback, CallbackProblem, CallbackQuery,
    ClientAuth, HttpFetcher, InMemoryLoginAttemptStore, LoginAttempt, LoginAttemptStore,
    ProviderMetadata, TokenBody,
};
use kirino::auth::relay::{origin_of, safe_return_path};
use kirino::error::KirinoError;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::state::AppState;

/// `AUTH_PROVIDER_GITHUB_CLIENT_ID`: the GitHub OAuth app's client id.
pub const GITHUB_CLIENT_ID_ENV: &str = "AUTH_PROVIDER_GITHUB_CLIENT_ID";
/// `AUTH_PROVIDER_GITHUB_CLIENT_SECRET`: optional; absent = public client.
pub const GITHUB_CLIENT_SECRET_ENV: &str = "AUTH_PROVIDER_GITHUB_CLIENT_SECRET";
/// `AUTH_PROVIDER_GOOGLE_CLIENT_ID`: the Google OAuth client's id.
pub const GOOGLE_CLIENT_ID_ENV: &str = "AUTH_PROVIDER_GOOGLE_CLIENT_ID";
/// `AUTH_PROVIDER_GOOGLE_CLIENT_SECRET`: optional; absent = public client.
pub const GOOGLE_CLIENT_SECRET_ENV: &str = "AUTH_PROVIDER_GOOGLE_CLIENT_SECRET";
/// `AUTH_PROVIDER_CELESTIA_CLIENT_ID`: the family IdP's client id.
pub const CELESTIA_CLIENT_ID_ENV: &str = "AUTH_PROVIDER_CELESTIA_CLIENT_ID";
/// `AUTH_PROVIDER_CELESTIA_CLIENT_SECRET`: REQUIRED with the client id —
/// the family IdP validates the secret on every exchange (no public-client
/// lane).
pub const CELESTIA_CLIENT_SECRET_ENV: &str = "AUTH_PROVIDER_CELESTIA_CLIENT_SECRET";
/// `AUTH_PUBLIC_BASE_URL`: this service's public origin (`https://mail.example`).
pub const PUBLIC_BASE_URL_ENV: &str = "AUTH_PUBLIC_BASE_URL";
/// Every provider variable; a deployment sets none of them or complete pairs.
pub const PROVIDER_ENV_VARS: &[&str] = &[
    GITHUB_CLIENT_ID_ENV,
    GITHUB_CLIENT_SECRET_ENV,
    GOOGLE_CLIENT_ID_ENV,
    GOOGLE_CLIENT_SECRET_ENV,
    CELESTIA_CLIENT_ID_ENV,
    CELESTIA_CLIENT_SECRET_ENV,
];

/// The family identity provider: the **one** IdP the family rules name
/// (`auth.celestia.world`, the personal face of the ERP OAuth service).
///
/// Hard-coded, not an environment variable, exactly like GitHub's and
/// Google's endpoints below: the deployment chooses whether to offer the
/// IdP, never which issuer it is. Its three endpoints are the issuer's
/// contract paths — `/oauth/authorize` is the consent page the browser
/// visits, `/api/oauth/token` and `/api/oauth/userinfo` are the server
/// legs — so they are derived from this one constant instead of being
/// spelled out three times.
pub const CELESTIA_ISSUER: &str = "https://auth.celestia.world";
/// The issuer's authorization (consent) endpoint.
pub const CELESTIA_AUTHORIZE_URL: &str = "https://auth.celestia.world/oauth/authorize";
/// The issuer's token endpoint.
pub const CELESTIA_TOKEN_URL: &str = "https://auth.celestia.world/api/oauth/token";
/// The issuer's UserInfo endpoint.
pub const CELESTIA_USERINFO_URL: &str = "https://auth.celestia.world/api/oauth/userinfo";

/// How long a ticket (the right to start one attempt) stays usable.
pub const TICKET_TTL: Duration = Duration::from_secs(10 * 60);
/// How long a started attempt may take at the provider.
pub const ATTEMPT_TTL: ChronoDuration = ChronoDuration::minutes(10);
/// How long an unclaimed handoff code stays redeemable. Short on purpose:
/// the code is a bearer for the session it mints.
pub const HANDOFF_TTL: Duration = Duration::from_secs(60);

/// The browser-binding cookie's name.
pub const BINDING_COOKIE: &str = "ayane_oauth_binding";
/// The path both OAuth routes live under; the binding cookie is scoped to it.
pub const OAUTH_PATH_PREFIX: &str = "/api/auth/oauth";

/// A provider configuration that cannot be honoured.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthConfigError {
    /// A provider variable is present but the set is incomplete.
    #[error("provider sign-in needs {0}")]
    Missing(&'static str),
    /// A variable is not a URL.
    #[error("{0} is not a valid URL: {1}")]
    InvalidUrl(&'static str, url::ParseError),
    /// A URL is neither https nor a loopback http origin.
    #[error("{0} must be https (http is allowed only for a loopback host)")]
    NotHttps(&'static str),
    /// A URL carries userinfo (`https://user:password@host`).
    #[error("{0} must not carry userinfo (user:password@ before the host)")]
    Userinfo(&'static str),
    /// The public base URL is anything but `scheme://host[:port]` plus an
    /// optional single `/`.
    #[error("{0} must be a bare origin (scheme://host[:port])")]
    NotAnOrigin(&'static str),
}

/// One configured provider: its endpoints plus the client credentials.
///
/// Not `Debug` on purpose — the confidential secret must never reach a
/// log line; [`ProviderCatalog`]'s `Debug` names providers by id only.
#[derive(Clone)]
pub struct Provider {
    /// The host's provider id (`github`, `google`, `celestia`).
    pub id: &'static str,
    /// The registered client (`Public` when no secret was configured).
    pub client: ClientAuth,
    /// Endpoints and encoding; `provider` equals `id`.
    pub metadata: ProviderMetadata,
}

/// Every provider this deployment offers, read from the environment.
#[derive(Clone)]
pub struct ProviderCatalog {
    providers: Vec<Provider>,
    public_base: Option<Url>,
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The authority of a URL as RAWLY spelled: the text between `scheme://`
/// and the first `/`, `?` or `#`. `None` when there is no `scheme://`.
///
/// The normalised [`Url`] is not enough for the checks below: it drops an
/// empty `user@`, folds `/.` and `/..` path segments into `/`, and strips
/// tab and newline characters anywhere in the input — each one a spelling
/// two parsers would read differently. The raw text is what was configured.
fn raw_authority(raw: &str) -> Option<&str> {
    let rest = raw.split_once("://")?.1;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Whether `raw` is spelled as a bare origin — `scheme://host[:port]`
/// followed by nothing but an optional single `/` — judged on the raw
/// string, not on a normalised path.
fn is_bare_origin(raw: &str) -> bool {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return false;
    };
    // One trailing `/` is the same origin; anything else after the
    // authority (a path, a second slash, a query, a fragment, a backslash
    // the `url` crate would read as a path separator) is not bare.
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    !scheme.is_empty()
        && !authority.is_empty()
        && !authority.bytes().any(|b| {
            matches!(b, b'/' | b'?' | b'#' | b'\\' | b'@')
                || b.is_ascii_whitespace()
                || b.is_ascii_control()
        })
}

fn parse_secure_url(raw: &str, name: &'static str) -> Result<Url, AuthConfigError> {
    let raw = raw.trim();
    let url = Url::parse(raw).map_err(|error| AuthConfigError::InvalidUrl(name, error))?;
    // MUT:no-userinfo — a URL that carries userinfo is refused outright.
    // `https://u:p@host` and `https://host` are different authorities to
    // every other parser (a browser, a proxy, curl) while the normalised
    // `Url` happily serves either; the operator wrote one host, so a
    // second one in front of the `@` is never honoured. The raw authority
    // is checked too: an empty `user@` leaves no trace on the `Url`.
    let userinfo = raw_authority(raw).is_some_and(|authority| authority.contains('@'))
        || !url.username().is_empty()
        || url.password().is_some();
    if userinfo {
        return Err(AuthConfigError::Userinfo(name));
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback(&url)) {
        return Err(AuthConfigError::NotHttps(name));
    }
    Ok(url)
}

fn parse_origin(raw: &str, name: &'static str) -> Result<Url, AuthConfigError> {
    let raw = raw.trim();
    let url = parse_secure_url(raw, name)?;
    // MUT:bare-origin-raw — "bare" is judged on the raw spelling. The
    // normalised path would accept `https://host/.` (folded to `/`) and
    // a host with an embedded tab (stripped): both carry more than an
    // origin, and a return address or redirect URI built on them would
    // not be the origin the operator believes they configured.
    if !is_bare_origin(raw) || url.host().is_none() {
        return Err(AuthConfigError::NotAnOrigin(name));
    }
    Ok(url)
}

fn endpoint(raw: &str) -> Url {
    Url::parse(raw).expect("built-in provider endpoint is a valid URL")
}

impl ProviderCatalog {
    /// A deployment without providers: password only.
    #[must_use]
    pub fn local() -> Self {
        Self {
            providers: Vec::new(),
            public_base: None,
        }
    }

    /// Read the catalog from the process environment.
    ///
    /// # Errors
    ///
    /// As [`from_env_with`](Self::from_env_with).
    pub fn from_env() -> Result<Self, AuthConfigError> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    /// Read the catalog through `read`.
    ///
    /// `Ok(empty)` when **no** provider variable is set. Otherwise the set
    /// must be complete — fail closed on *presence*, never on content: a
    /// provider variable that is set but blank means "federated was
    /// intended", never "no providers" (a template that sets only a
    /// secret must not start up as a password-only deployment). Each
    /// provider named needs its client id; the secret is optional (absent
    /// = public client, PKCE is then the only proof). [`PUBLIC_BASE_URL_ENV`]
    /// is required as soon as any provider is configured.
    ///
    /// # Errors
    ///
    /// [`AuthConfigError`] naming the first offending variable.
    pub fn from_env_with(read: impl Fn(&str) -> Option<String>) -> Result<Self, AuthConfigError> {
        let value = |name: &'static str| -> Option<String> {
            read(name)
                .map(|raw| raw.trim().to_owned())
                .filter(|raw| !raw.is_empty())
        };
        let public_base = match value(PUBLIC_BASE_URL_ENV) {
            Some(raw) => Some(parse_origin(&raw, PUBLIC_BASE_URL_ENV)?),
            None => None,
        };
        let mut providers = Vec::new();
        for built_in in BUILT_INS {
            if read(built_in.client_id_env).is_none() && read(built_in.client_secret_env).is_none()
            {
                continue;
            }
            let client_id = value(built_in.client_id_env)
                .ok_or(AuthConfigError::Missing(built_in.client_id_env))?;
            // The family IdP has no public-client lane: its token endpoint
            // validates the client secret unconditionally, so a `celestia`
            // row without a secret is a deployment that 401s at the
            // exchange — refused here, at startup, where it is fixable.
            if built_in.id == "celestia" && value(built_in.client_secret_env).is_none() {
                return Err(AuthConfigError::Missing(CELESTIA_CLIENT_SECRET_ENV));
            }
            let client = match value(built_in.client_secret_env) {
                Some(secret) => ClientAuth::Confidential {
                    client_id,
                    // `Zeroizing` by conversion (kirino's type, zeroize's
                    // `From`): the secret is wiped when the catalog drops.
                    client_secret: secret.into(),
                },
                None => ClientAuth::Public { client_id },
            };
            providers.push(Provider {
                id: built_in.id,
                client,
                metadata: ProviderMetadata {
                    provider: built_in.id.to_owned(),
                    issuer: built_in.issuer.map(str::to_owned),
                    authorize_url: endpoint(built_in.authorize_url),
                    token_url: endpoint(built_in.token_url),
                    userinfo_url: Some(endpoint(built_in.userinfo_url)),
                    token_body: built_in.token_body,
                    scopes: built_in.scopes.iter().map(|s| (*s).to_owned()).collect(),
                },
            });
        }
        if !providers.is_empty() && public_base.is_none() {
            return Err(AuthConfigError::Missing(PUBLIC_BASE_URL_ENV));
        }
        Ok(Self {
            providers,
            public_base,
        })
    }

    /// Whether any provider is configured.
    #[must_use]
    pub fn has_providers(&self) -> bool {
        !self.providers.is_empty()
    }

    /// The configured provider with this id.
    #[must_use]
    pub fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|provider| provider.id == id)
    }

    /// This service's public origin, when configured.
    #[must_use]
    pub fn public_base(&self) -> Option<&Url> {
        self.public_base.as_ref()
    }

    /// The `scheme://host[:port]` a return address may name: this service.
    #[must_use]
    pub fn return_origins(&self) -> Vec<String> {
        self.public_base
            .as_ref()
            .map(|base| vec![origin_of(base)])
            .unwrap_or_default()
    }

    /// The discovery document for this deployment.
    ///
    /// `LoginPolicy::local()` with no providers; otherwise `federated`,
    /// password kept, one `oauth` entrance per provider in display order.
    /// The `label` carries the provider id: the webui localises it, the
    /// server never picks a display language.
    #[must_use]
    pub fn login_policy(&self) -> LoginPolicy {
        if self.providers.is_empty() {
            return LoginPolicy::local();
        }
        LoginPolicy {
            version: LOGIN_POLICY_VERSION,
            mode: AuthMode::Federated,
            password: true,
            methods: self
                .providers
                .iter()
                .map(|provider| {
                    LoginMethodDescriptor::oauth(
                        provider.id,
                        format!("{OAUTH_PATH_PREFIX}/{}", provider.id),
                        provider.id,
                    )
                })
                .collect(),
            relay: None,
        }
    }

    /// The document, checked: refuses to serve a policy that disagrees
    /// with itself.
    ///
    /// # Errors
    ///
    /// The first [`kirino::auth::mode::LoginPolicyViolation`]; the caller
    /// must refuse to start on it.
    pub fn validated_login_policy(
        &self,
    ) -> Result<LoginPolicy, kirino::auth::mode::LoginPolicyViolation> {
        let policy = self.login_policy();
        policy.validate()?;
        Ok(policy)
    }

    /// The registered callback URL of `provider` (`{base}/api/auth/oauth/{id}/callback`).
    ///
    /// `None` without a public base (a provider without one cannot be
    /// configured, but a caller must still not have to guess).
    #[must_use]
    pub fn redirect_uri(&self, provider: &str) -> Option<Url> {
        let mut url = self.public_base.as_ref()?.clone();
        url.set_path(&format!("{OAUTH_PATH_PREFIX}/{provider}/callback"));
        Some(url)
    }
}

/// The endpoints of a provider ayane knows out of the box.
struct BuiltIn {
    id: &'static str,
    client_id_env: &'static str,
    client_secret_env: &'static str,
    authorize_url: &'static str,
    token_url: &'static str,
    userinfo_url: &'static str,
    issuer: Option<&'static str>,
    token_body: TokenBody,
    scopes: &'static [&'static str],
}

/// GitHub (opaque subjects, JSON token endpoint) then Google (OIDC issuer),
/// then the family IdP (an OIDC-shaped issuer with a form token endpoint).
///
/// The order is the display order every login panel renders.
const BUILT_INS: &[BuiltIn] = &[
    BuiltIn {
        id: "github",
        client_id_env: GITHUB_CLIENT_ID_ENV,
        client_secret_env: GITHUB_CLIENT_SECRET_ENV,
        authorize_url: "https://github.com/login/oauth/authorize",
        token_url: "https://github.com/login/oauth/access_token",
        userinfo_url: "https://api.github.com/user",
        issuer: None,
        token_body: TokenBody::Json,
        scopes: &["read:user", "user:email"],
    },
    BuiltIn {
        id: "google",
        client_id_env: GOOGLE_CLIENT_ID_ENV,
        client_secret_env: GOOGLE_CLIENT_SECRET_ENV,
        authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
        issuer: Some("https://accounts.google.com"),
        token_body: TokenBody::Form,
        scopes: &["openid", "profile", "email"],
    },
    BuiltIn {
        // MUT:celestia-endpoints — the family IdP's three paths are the
        // issuer's contract (consent page under `/oauth`, both API legs
        // under `/api/oauth`); deriving them from one constant keeps the
        // three from drifting apart.
        id: "celestia",
        client_id_env: CELESTIA_CLIENT_ID_ENV,
        client_secret_env: CELESTIA_CLIENT_SECRET_ENV,
        authorize_url: CELESTIA_AUTHORIZE_URL,
        token_url: CELESTIA_TOKEN_URL,
        userinfo_url: CELESTIA_USERINFO_URL,
        issuer: Some(CELESTIA_ISSUER),
        // RFC 6749 §4.1.3 form body: what the ERP OAuth service accepts
        // first (it also takes JSON, for chest's built-in `erp` provider).
        token_body: TokenBody::Form,
        scopes: &["openid", "profile", "email"],
    },
];

impl std::fmt::Debug for ProviderCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ids only: a confidential client's secret never reaches a log line.
        let ids: Vec<&str> = self.providers.iter().map(|provider| provider.id).collect();
        f.debug_struct("ProviderCatalog")
            .field("providers", &ids)
            .field("public_base", &self.public_base)
            .finish()
    }
}

/// [`HttpFetcher`] over `reqwest`, **INTERIM**.
///
/// This is ayane's local copy of the posture plana's `identity_relay`
/// member defines (no redirects, a bounded timeout, JSON only, errors
/// without the request URL and never with the response body). It exists
/// only because ayane is still on `reqwest` 0.12 and plana's member needs
/// 0.13: **swap this for `plana-identity-relay` once it publishes and
/// ayane moves to reqwest 0.13.** Nothing protocol-related lives here —
/// the requests are exactly the ones kirino's `finish` builds.
#[derive(Clone)]
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    /// The family posture: no redirects, 15 s total timeout.
    ///
    /// # Errors
    ///
    /// When the HTTP client cannot be built (the error never carries a URL).
    pub fn new() -> Result<Self, AuthError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| AuthError::Transport(error.without_url().to_string()))?;
        Ok(Self { client })
    }

    /// The answer as JSON, or the status alone — the body may echo input.
    async fn json(response: reqwest::Response) -> anyhow::Result<Value> {
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("identity provider answered {status}"));
        }
        response.json().await.map_err(|error| {
            anyhow!(
                "identity provider answer unreadable: {}",
                error.without_url()
            )
        })
    }
}

#[async_trait]
impl HttpFetcher for ReqwestFetcher {
    async fn post_form(&self, url: &Url, params: &[(&str, &str)]) -> anyhow::Result<Value> {
        let response = self
            .client
            .post(url.as_str())
            .form(params)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| anyhow!("identity provider unreachable: {}", error.without_url()))?;
        Self::json(response).await
    }

    async fn post_json(&self, url: &Url, body: &Value) -> anyhow::Result<Value> {
        let response = self
            .client
            .post(url.as_str())
            .json(body)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| anyhow!("identity provider unreachable: {}", error.without_url()))?;
        Self::json(response).await
    }

    async fn get_bearer(&self, url: &Url, access_token: &str) -> anyhow::Result<Value> {
        let response = self
            .client
            .get(url.as_str())
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| anyhow!("identity provider unreachable: {}", error.without_url()))?;
        Self::json(response).await
    }
}

/// A fetcher for a deployment without providers: nothing can reach it
/// (no provider is configured, so no attempt is ever started), and it
/// answers a closed refusal rather than opening a socket.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFetcher;

#[async_trait]
impl HttpFetcher for NoFetcher {
    async fn post_form(&self, _url: &Url, _params: &[(&str, &str)]) -> anyhow::Result<Value> {
        Err(anyhow!("provider sign-in is not configured"))
    }

    async fn post_json(&self, _url: &Url, _body: &Value) -> anyhow::Result<Value> {
        Err(anyhow!("provider sign-in is not configured"))
    }

    async fn get_bearer(&self, _url: &Url, _access_token: &str) -> anyhow::Result<Value> {
        Err(anyhow!("provider sign-in is not configured"))
    }
}

/// A federated sign-in step failed outside the callback's own vocabulary.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The provider is not configured on this deployment.
    #[error("provider {0} is not configured")]
    UnknownProvider(String),
    /// Federated sign-in is not configured (no public base URL).
    #[error("provider sign-in is not configured")]
    NotConfigured,
    /// The transport could not be built.
    #[error("identity transport: {0}")]
    Transport(String),
    /// The snapshot store failed.
    #[error("store: {0}")]
    Store(String),
    /// The mailbox behind a session or a link no longer exists.
    #[error("the mailbox no longer exists")]
    AccountMissing,
}

/// A fresh opaque code (32 random bytes, hex) — tickets, handoff codes and
/// the browser binding all draw from it.
fn random_code() -> Result<String, AuthError> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw)
        .map_err(|_| AuthError::Transport("entropy unavailable".to_owned()))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

// ── identity links over the snapshot store ────────────────────────────────

/// [`ExternalIdentityStore`] over the snapshot store.
///
/// The trait's `user_id` is ayane's account `id`, resolved against the
/// live account table on every call: an account's id is minted afresh by
/// each whole-state replacement, so the **address** is what a link
/// stores ([`ExternalLink`]) and the id is only the handle a caller
/// (which holds a session, hence an address) passes in. Every mutation
/// runs through [`StateStore::update`], so the one-identity-one-account
/// check and the write are one locked step.
#[derive(Clone)]
pub struct IdentityLinks {
    store: Arc<dyn StateStore>,
}

impl IdentityLinks {
    /// Links backed by `store`.
    #[must_use]
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }

    /// The normalised key a stored link answers to.
    fn key_of(link: &ExternalLink) -> ExternalIdentity {
        ExternalIdentity {
            provider: link.provider.clone(),
            issuer: link.issuer.clone(),
            subject: link.subject.clone(),
        }
        .normalised()
    }

    /// The account row with `id`, or a rejection.
    fn account_of(
        state: &StoredState,
        user_id: uuid::Uuid,
    ) -> Result<&ayane_proto::Account, ayane_store::StoreError> {
        state
            .desired
            .accounts
            .iter()
            .find(|account| account.id == user_id)
            .ok_or_else(|| {
                ayane_store::StoreError::Rejected("the account no longer exists".to_owned())
            })
    }

    /// Every link of `address`, oldest first (the tie-break keeps the
    /// order reproducible for links created in one timestamp).
    fn rows_of(state: &StoredState, address: &Address) -> Vec<ExternalLink> {
        let mut found: Vec<ExternalLink> = state
            .external_identities
            .iter()
            .filter(|link| link.address == *address)
            .cloned()
            .collect();
        found.sort_by(|a, b| (a.created_at, &a.provider).cmp(&(b.created_at, &b.provider)));
        found
    }

    /// The account behind a session address: its live `id`.
    ///
    /// # Errors
    ///
    /// [`AuthError::AccountMissing`] when the mailbox no longer exists.
    pub fn account_id_of(&self, address: &Address) -> Result<uuid::Uuid, AuthError> {
        self.store
            .load()
            .map_err(|e| AuthError::Store(e.to_string()))?
            .desired
            .accounts
            .iter()
            .find(|account| account.address == *address)
            .map(|account| account.id)
            .ok_or(AuthError::AccountMissing)
    }
}

#[async_trait]
impl ExternalIdentityStore for IdentityLinks {
    async fn find_user(
        &self,
        identity: &ExternalIdentity,
    ) -> anyhow::Result<Option<LinkedAccount>> {
        let key = identity.normalised();
        let stored = self.store.load().map_err(anyhow::Error::from)?;
        let Some(link) = stored
            .external_identities
            .iter()
            .find(|link| Self::key_of(link) == key)
        else {
            return Ok(None);
        };
        // A link whose account was removed is an orphan: it answers "not
        // linked" and is never a way back into a re-created mailbox.
        let Some(account) = stored
            .desired
            .accounts
            .iter()
            .find(|account| account.address == link.address)
        else {
            return Ok(None);
        };
        Ok(Some(LinkedAccount {
            identity: Self::key_of(link),
            user_id: account.id,
            created_at: link.created_at,
            last_login_at: link.last_login_at,
        }))
    }

    async fn link(
        &self,
        identity: &ExternalIdentity,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<LinkOutcome> {
        identity.validate()?;
        let key = identity.normalised();
        let mut outcome = LinkOutcome::Linked;
        self.store
            .update(&mut |state| {
                let address = Self::account_of(state, user_id)?.address.clone();
                if let Some(existing) = state
                    .external_identities
                    .iter()
                    .find(|link| Self::key_of(link) == key)
                {
                    if existing.address == address {
                        outcome = LinkOutcome::AlreadyLinked;
                        return Ok(());
                    }
                    // MUT:exclusive-link — one identity belongs to exactly one
                    // account; a second account is refused, never merged or
                    // re-pointed, and the check sits inside the locked write.
                    return Err(ayane_store::StoreError::Rejected(format!(
                        "external identity is already linked to another account ({})",
                        existing.address
                    )));
                }
                state.external_identities.push(ExternalLink {
                    provider: key.provider.clone(),
                    issuer: key.issuer.clone(),
                    subject: key.subject.clone(),
                    address,
                    created_at: Utc::now(),
                    last_login_at: None,
                });
                Ok(())
            })
            .map_err(|e| match e {
                ayane_store::StoreError::Rejected(prose) => {
                    KirinoError::ConstraintViolation(prose).into()
                }
                other => anyhow::Error::from(other),
            })?;
        Ok(outcome)
    }

    async fn unlink(
        &self,
        identity: &ExternalIdentity,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<bool> {
        let key = identity.normalised();
        let mut removed = false;
        self.store
            .update(&mut |state| {
                // Only the owner may remove a link: a non-owner's call must
                // leave the link in place, so the owner check precedes the
                // removal. Always allowed for the owner — an own-domain
                // account keeps its password whatever is linked.
                let address = Self::account_of(state, user_id)?.address.clone();
                let before = state.external_identities.len();
                state
                    .external_identities
                    .retain(|link| !(Self::key_of(link) == key && link.address == address));
                removed = state.external_identities.len() != before;
                Ok(())
            })
            .map_err(anyhow::Error::from)?;
        Ok(removed)
    }

    async fn list_for_user(&self, user_id: uuid::Uuid) -> anyhow::Result<Vec<LinkedAccount>> {
        let stored = self.store.load().map_err(anyhow::Error::from)?;
        let address = Self::account_of(&stored, user_id)
            .map_err(anyhow::Error::from)?
            .address
            .clone();
        Ok(Self::rows_of(&stored, &address)
            .into_iter()
            .map(|link| LinkedAccount {
                identity: Self::key_of(&link),
                user_id,
                created_at: link.created_at,
                last_login_at: link.last_login_at,
            })
            .collect())
    }

    async fn record_login(&self, identity: &ExternalIdentity) -> anyhow::Result<()> {
        let key = identity.normalised();
        self.store
            .update(&mut |state| {
                // A no-op for an unknown identity (the link may have been
                // removed meanwhile).
                if let Some(link) = state
                    .external_identities
                    .iter_mut()
                    .find(|link| Self::key_of(link) == key)
                {
                    link.last_login_at = Some(Utc::now());
                }
                Ok(())
            })
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
}

// ── in-flight sign-ins ────────────────────────────────────────────────────

/// What a started sign-in is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptPurpose {
    /// Sign in; land on `return_to` (a same-origin path) afterwards.
    Login {
        /// Where the browser asked to land, already sanitised.
        return_to: Option<String>,
    },
    /// Link the identity to the authenticated account `address`.
    Link {
        /// The mailbox the authenticated session belongs to.
        address: Address,
    },
}

/// A finished sign-in waiting for the SPA to claim it.
#[derive(Clone, PartialEq, Eq)]
pub struct Handoff {
    /// The mailbox the identity is linked to.
    pub address: Address,
    /// Display name from the desired state.
    pub display_name: String,
    /// Whether the account administers the service.
    pub admin: bool,
    /// The cached credential of an account that has one; `None` = the
    /// mailbox password is needed (an own-domain account).
    pub credential: Option<String>,
    /// Where the browser asked to land.
    pub return_to: Option<String>,
    expires: Instant,
}

impl Handoff {
    /// A finished sign-in that may be claimed from now on for
    /// [`HANDOFF_TTL`] — the one place that lifetime is stamped. Parking
    /// stores the handoff as it is given.
    #[must_use]
    pub fn new(
        address: Address,
        display_name: String,
        admin: bool,
        credential: Option<String>,
        return_to: Option<String>,
    ) -> Self {
        Self {
            address,
            display_name,
            admin,
            credential,
            return_to,
            expires: Instant::now() + HANDOFF_TTL,
        }
    }
}

impl std::fmt::Debug for Handoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credential is a secret for the handoff's lifetime.
        f.debug_struct("Handoff")
            .field("address", &self.address)
            .field("display_name", &self.display_name)
            .field("admin", &self.admin)
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[redacted]"),
            )
            .field("return_to", &self.return_to)
            .field("expires", &self.expires)
            .finish()
    }
}

/// The right to start one attempt, handed to the SPA exactly once. The
/// attempt itself rides the ticket: the browser is redirected with it
/// here, while kirino's own store keeps the copy `finish` spends.
struct Ticket {
    attempt: LoginAttempt,
    purpose: AttemptPurpose,
    expires: Instant,
}

/// Why [`AttemptStore::take_ticket_for`] did not spend a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketRefusal {
    /// No live ticket by that value: never issued, already spent, or
    /// expired.
    Unknown,
    /// The ticket names another provider. Nothing was consumed.
    Mismatch,
}

/// The in-memory side of federated sign-in: kirino's one-time attempt
/// store, the tickets that unlock an attempt, the purpose parked behind
/// each `state` (the browser only carries the state back) and the
/// finished sign-ins waiting to be claimed. Nothing here survives a
/// restart — an in-flight sign-in simply starts over — and nothing here
/// is ever persisted.
#[derive(Default)]
pub struct AttemptStore {
    attempts: InMemoryLoginAttemptStore,
    tickets: Mutex<HashMap<String, Ticket>>,
    purposes: Mutex<HashMap<String, (AttemptPurpose, Instant)>>,
    handoffs: Mutex<HashMap<String, Handoff>>,
}

impl AttemptStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop everything that has expired (each map is swept when it grows).
    fn sweep(&self) {
        let now = Instant::now();
        self.tickets
            .lock()
            .expect("tickets mutex")
            .retain(|_, ticket| ticket.expires > now);
        self.purposes
            .lock()
            .expect("purposes mutex")
            .retain(|_, (_, expires)| *expires > now);
        self.handoffs
            .lock()
            .expect("handoffs mutex")
            .retain(|_, handoff| handoff.expires > now);
    }

    /// Start an attempt for `provider` and park it behind a one-time
    /// ticket. The attempt is bound to a fresh browser binding, which the
    /// start route hands to the browser in the binding cookie.
    ///
    /// # Errors
    ///
    /// [`AuthError::Transport`] when the parking fails.
    pub async fn begin(
        &self,
        provider: &str,
        purpose: AttemptPurpose,
    ) -> Result<(String, LoginAttempt), AuthError> {
        self.sweep();
        // MUT:bound-attempt — every attempt carries a browser binding; an
        // unbound one could be completed by any browser (login CSRF).
        let binding = random_code()?;
        let return_to = match &purpose {
            AttemptPurpose::Login { return_to } => return_to.clone(),
            AttemptPurpose::Link { .. } => None,
        };
        let attempt = begin_with_binding(
            &self.attempts,
            provider,
            return_to,
            Some(binding),
            ATTEMPT_TTL,
        )
        .await
        .map_err(|e| AuthError::Transport(e.to_string()))?;
        self.purposes.lock().expect("purposes mutex").insert(
            attempt.state.clone(),
            (purpose.clone(), Instant::now() + TICKET_TTL),
        );
        let ticket = random_code()?;
        self.tickets.lock().expect("tickets mutex").insert(
            ticket.clone(),
            Ticket {
                attempt: attempt.clone(),
                purpose,
                expires: Instant::now() + TICKET_TTL,
            },
        );
        Ok((ticket, attempt))
    }

    /// Spend a ticket — and only on the route of the provider it was
    /// minted for. The provider check and the removal are one step under
    /// the tickets lock, so a mismatch leaves the ticket exactly where it
    /// was: the browser that took a wrong turn can still spend it on the
    /// right route. This is the ONLY way a ticket is spent.
    pub fn take_ticket_for(
        &self,
        ticket: &str,
        provider: &str,
    ) -> Result<(LoginAttempt, AttemptPurpose), TicketRefusal> {
        let mut tickets = self.tickets.lock().expect("tickets mutex");
        let live = tickets
            .get(ticket)
            .filter(|live| live.expires > Instant::now());
        let Some(live) = live else {
            return Err(TicketRefusal::Unknown);
        };
        if live.attempt.provider != provider {
            return Err(TicketRefusal::Mismatch);
        }
        let Some(taken) = tickets.remove(ticket) else {
            return Err(TicketRefusal::Unknown);
        };
        Ok((taken.attempt, taken.purpose))
    }

    /// The purpose parked behind `state`, taken out (the attempt is spent
    /// in the same callback).
    fn take_purpose(&self, state: &str) -> Option<AttemptPurpose> {
        self.purposes
            .lock()
            .expect("purposes mutex")
            .remove(state)
            .filter(|(_, expires)| *expires > Instant::now())
            .map(|(purpose, _)| purpose)
    }

    /// Park a finished sign-in and return the one-time code that claims it.
    /// The handoff is stored as given, its lifetime included: the code is
    /// dead the moment that lifetime has passed, whenever it is claimed.
    #[must_use]
    pub fn park_handoff(&self, handoff: Handoff) -> String {
        let code = random_code().unwrap_or_else(|_| uuid::Uuid::new_v4().simple().to_string());
        self.handoffs
            .lock()
            .expect("handoffs mutex")
            .insert(code.clone(), handoff);
        code
    }

    /// Claim a finished sign-in: exactly once, never an expired one.
    pub fn take_handoff(&self, code: &str) -> Option<Handoff> {
        let taken = self.handoffs.lock().expect("handoffs mutex").remove(code)?;
        // MUT:handoff-expiry — the sweep only runs when a map grows, so
        // this check is what refuses a code that outlived HANDOFF_TTL: it
        // is taken out and answers nothing, as if it never existed.
        (taken.expires > Instant::now()).then_some(taken)
    }
}

#[async_trait]
impl LoginAttemptStore for AttemptStore {
    async fn put(&self, attempt: LoginAttempt) -> anyhow::Result<()> {
        self.attempts.put(attempt).await
    }

    async fn take(&self, state: &str) -> anyhow::Result<Option<LoginAttempt>> {
        self.attempts.take(state).await
    }
}

/// The federated sign-in state every handler shares: the catalog, the
/// in-flight sign-ins and the identity transport.
pub struct AuthState {
    /// What this deployment offers.
    pub catalog: ProviderCatalog,
    /// In-flight sign-ins.
    pub attempts: AttemptStore,
    /// The transport kirino's `finish` speaks through.
    pub http: Arc<dyn HttpFetcher>,
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("catalog", &self.catalog)
            .finish_non_exhaustive()
    }
}

impl AuthState {
    /// The state for a configured deployment.
    #[must_use]
    pub fn new(catalog: ProviderCatalog, http: Arc<dyn HttpFetcher>) -> Self {
        Self {
            catalog,
            attempts: AttemptStore::new(),
            http,
        }
    }

    /// A password-only deployment: no providers, no transport to reach.
    #[must_use]
    pub fn local() -> Self {
        Self::new(ProviderCatalog::local(), Arc::new(NoFetcher))
    }
}

/// The reason a sign-in failed, as the SPA reads it back from the
/// redirect: a closed vocabulary — never a provider's prose, never a
/// token, never a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthError {
    /// The provider answered with an OAuth error (the visitor declined, …).
    Denied,
    /// The callback carried no state, or one never issued, spent or expired.
    State,
    /// The callback carried no code.
    Code,
    /// The callback did not come from the browser that started the sign-in.
    Binding,
    /// The ticket or callback was presented on another provider's route
    /// than the attempt was started for.
    MismatchProvider,
    /// The token endpoint's answer was unusable.
    Token,
    /// The provider returned no usable subject.
    Identity,
    /// The provider could not be reached.
    Unreachable,
    /// The provider is not configured here.
    UnknownProvider,
    /// Federated sign-in is not configured here (no public base URL).
    NotConfigured,
    /// The identity is not linked to any mailbox.
    Unlinked,
    /// The identity is already linked to another mailbox.
    AlreadyLinked,
    /// Linking failed for another reason.
    LinkFailed,
    /// The snapshot store failed.
    Store,
}

impl From<CallbackProblem> for OAuthError {
    fn from(problem: CallbackProblem) -> Self {
        match problem {
            CallbackProblem::ProviderDenied { .. } => Self::Denied,
            CallbackProblem::MissingState | CallbackProblem::UnknownState => Self::State,
            CallbackProblem::MissingCode => Self::Code,
            CallbackProblem::BindingMismatch => Self::Binding,
            CallbackProblem::ProviderMismatch => Self::MismatchProvider,
            CallbackProblem::TokenInvalid(_) | CallbackProblem::IdTokenInvalid(_) => Self::Token,
            CallbackProblem::IdentityEmpty => Self::Identity,
            CallbackProblem::Transport(_) => Self::Unreachable,
        }
    }
}

impl OAuthError {
    /// The wire spelling (the `oauth_error` query value).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::State => "state",
            Self::Code => "code",
            Self::Binding => "binding",
            Self::MismatchProvider => "mismatch_provider",
            Self::Token => "token",
            Self::Identity => "identity",
            Self::Unreachable => "unreachable",
            Self::UnknownProvider => "unknown_provider",
            Self::NotConfigured => "not_configured",
            Self::Unlinked => "unlinked",
            Self::AlreadyLinked => "already_linked",
            Self::LinkFailed => "link_failed",
            Self::Store => "store",
        }
    }
}

/// Normalise a return address the SPA asked for: a same-origin path, or an
/// absolute URL on this service's own origin reduced to its path. Anything
/// else is dropped (`None`) — a foreign origin is never forwarded.
#[must_use]
pub fn safe_return_to(catalog: &ProviderCatalog, raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    safe_return_path(raw, &catalog.return_origins())
}

/// `session.oauthBegin`: start a sign-in and answer the same-origin path
/// the browser navigates to (the one-time ticket rides its query).
///
/// # Errors
///
/// [`AuthError::UnknownProvider`] for a provider this deployment does not
/// offer, [`AuthError::NotConfigured`] without a public base URL.
pub async fn begin(
    app: &AppState,
    provider: &str,
    purpose: AttemptPurpose,
) -> Result<String, AuthError> {
    if app.auth.catalog.provider(provider).is_none() {
        return Err(AuthError::UnknownProvider(provider.to_owned()));
    }
    if app.auth.catalog.public_base().is_none() {
        return Err(AuthError::NotConfigured);
    }
    let (ticket, _) = app.auth.attempts.begin(provider, purpose).await?;
    Ok(format!("{OAUTH_PATH_PREFIX}/{provider}?ticket={ticket}"))
}

/// Where the callback sends the browser.
#[derive(Debug, PartialEq, Eq)]
pub enum CallbackOutcome {
    /// Signed in: the SPA claims the handoff code.
    Handoff {
        /// The one-time code.
        code: String,
    },
    /// Linked: the account page confirms the provider.
    Linked {
        /// The provider that was linked.
        provider: String,
    },
    /// Failed: the SPA shows the reason.
    Failed {
        /// The closed-vocabulary reason.
        reason: OAuthError,
        /// `true` when the sign-in was a link attempt (the browser is
        /// sent back to the account page, not the login page).
        link: bool,
    },
}

/// Turn the provider's redirect into a session handoff or a link.
///
/// Everything the callback decides happens here: the binding check and
/// the protocol are kirino's (`finish`); the account policy is ayane's.
pub async fn complete(
    app: &AppState,
    provider: &str,
    query: &CallbackQuery,
    binding: Option<&str>,
) -> CallbackOutcome {
    let fail = |reason: OAuthError, link: bool| CallbackOutcome::Failed { reason, link };
    let Some(built_in) = app.auth.catalog.provider(provider) else {
        return fail(OAuthError::UnknownProvider, false);
    };
    let Some(redirect_uri) = app.auth.catalog.redirect_uri(provider) else {
        return fail(OAuthError::NotConfigured, false);
    };
    // The purpose rides the state — the browser carries nothing else back.
    // MUT:purpose-with-state — a callback whose state has no parked purpose
    // (never issued here, or a restart) must not sign anybody in.
    let purpose = query
        .state
        .as_deref()
        .and_then(|state| app.auth.attempts.take_purpose(state));
    let link = matches!(purpose, Some(AttemptPurpose::Link { .. }));
    let finished = finish(
        app.auth.http.as_ref(),
        &app.auth.attempts,
        &built_in.metadata,
        &built_in.client,
        &redirect_uri,
        Callback::new(query, binding, &[]),
    )
    .await;
    let login = match finished {
        Ok(login) => login,
        Err(problem) => return fail(problem.into(), link),
    };
    let Some(purpose) = purpose else {
        return fail(OAuthError::State, link);
    };
    match purpose {
        AttemptPurpose::Link { address } => {
            link_identity(app, &login.identity, &address, provider).await
        }
        AttemptPurpose::Login { .. } => {
            sign_in(app, &login.identity, login.return_to.as_deref()).await
        }
    }
}

/// The sign-in leg: the identity must already be linked; the session is
/// parked behind a handoff for the SPA to claim.
async fn sign_in(
    app: &AppState,
    identity: &ExternalIdentity,
    return_to: Option<&str>,
) -> CallbackOutcome {
    let failed = |reason| CallbackOutcome::Failed {
        reason,
        link: false,
    };
    let links = IdentityLinks::new(app.store.clone());
    let account = match links.find_user(identity).await {
        Ok(Some(account)) => account,
        // MUT:link-only-first-sign-in — a provider identity nobody linked
        // is refused; it never opens a mailbox and never provisions one.
        Ok(None) => return failed(OAuthError::Unlinked),
        Err(_) => return failed(OAuthError::Store),
    };
    let Ok(stored) = app.store.load() else {
        return failed(OAuthError::Store);
    };
    let Some(row) = stored
        .desired
        .accounts
        .iter()
        .find(|row| row.id == account.user_id)
    else {
        return failed(OAuthError::Store);
    };
    // MUT:no-implicit-credential — an own-domain account has no cached
    // credential: the mailbox password is asked for once on the verify
    // card. Only a forwarding-node account (cached credential) skips it.
    // MUT:handoff-ttl — the construction site stamps the code's lifetime
    // ([`Handoff::new`]): `park_handoff` keeps it as stamped, never longer.
    let handoff = Handoff::new(
        row.address.clone(),
        row.display_name.clone(),
        row.admin,
        stored.cached_credential(&row.address),
        return_to.map(str::to_owned),
    );
    let code = app.auth.attempts.park_handoff(handoff);
    let _ = links.record_login(identity).await;
    CallbackOutcome::Handoff { code }
}

/// The link leg: an authenticated session asked for this identity to be
/// linked to its own mailbox.
async fn link_identity(
    app: &AppState,
    identity: &ExternalIdentity,
    address: &Address,
    provider: &str,
) -> CallbackOutcome {
    let links = IdentityLinks::new(app.store.clone());
    let Ok(user_id) = links.account_id_of(address) else {
        return CallbackOutcome::Failed {
            reason: OAuthError::LinkFailed,
            link: true,
        };
    };
    match links.link(identity, user_id).await {
        Ok(LinkOutcome::Linked | LinkOutcome::AlreadyLinked) => CallbackOutcome::Linked {
            provider: provider.to_owned(),
        },
        // MUT:one-identity-one-account — an identity that belongs to another
        // mailbox is refused here; the link never moves.
        Err(e)
            if e.downcast_ref::<KirinoError>()
                .is_some_and(|k| matches!(k, KirinoError::ConstraintViolation(_))) =>
        {
            CallbackOutcome::Failed {
                reason: OAuthError::AlreadyLinked,
                link: true,
            }
        }
        Err(_) => CallbackOutcome::Failed {
            reason: OAuthError::LinkFailed,
            link: true,
        },
    }
}

// ── browser routes ────────────────────────────────────────────────────────

/// The browser-facing sign-in routes, mounted beside `/api/health`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/login-methods", get(login_methods))
        .route("/api/auth/oauth/{provider}", get(oauth_start))
        .route("/api/auth/oauth/{provider}/callback", get(oauth_callback))
}

/// `GET /api/auth/login-methods` — the discovery document.
async fn login_methods(State(app): State<AppState>) -> Json<LoginPolicy> {
    Json(app.auth.catalog.login_policy())
}

/// The query pairs of a raw query string, decoded. A malformed query is
/// an empty list: a callback must redirect with a reason, never 400.
fn query_pairs_of(query: &str) -> Vec<(String, String)> {
    Url::parse(&format!("http://callback/?{query}"))
        .map(|url| {
            url.query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

/// The callback's query as kirino reads it.
fn callback_query(query: &str) -> CallbackQuery {
    let pairs = query_pairs_of(query);
    let first = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    CallbackQuery {
        code: first("code"),
        state: first("state"),
        error: first("error"),
        error_description: first("error_description"),
    }
}

/// The first cookie named `name`.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

/// The browser-binding cookie. `max_age` 0 clears it.
fn binding_cookie(value: &str, max_age: u32, secure: bool) -> String {
    format!(
        "{BINDING_COOKIE}={value}; HttpOnly; SameSite=Lax; Path={OAUTH_PATH_PREFIX}; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// A 302 to a same-origin path, with cookies to set.
fn redirect(location: String, cookies: Vec<String>) -> Response {
    let value = HeaderValue::from_str(&location)
        .unwrap_or_else(|_| HeaderValue::from_static("/login?oauth_error=state"));
    let mut response = (StatusCode::FOUND, [(header::LOCATION, value)]).into_response();
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn is_secure(app: &AppState) -> bool {
    app.auth
        .catalog
        .public_base()
        .is_some_and(|base| base.scheme() == "https")
}

fn failure(reason: OAuthError) -> Response {
    redirect(
        format!("/login?oauth_error={}", reason.as_str()),
        Vec::new(),
    )
}

/// `GET /api/auth/oauth/{provider}?ticket=…` — spend the ticket, bind the
/// attempt to this browser, send it to the provider.
///
/// Nothing is spent before the route's provider is known to the catalog:
/// an unknown provider, or one without a public base, is refused by name
/// and a real ticket in that request stays spendable on its own route.
async fn oauth_start(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(built_in) = app.auth.catalog.provider(&provider) else {
        return failure(OAuthError::UnknownProvider);
    };
    let Some(redirect_uri) = app.auth.catalog.redirect_uri(&provider) else {
        return failure(OAuthError::NotConfigured);
    };
    let Some(ticket) = query
        .as_deref()
        .and_then(|raw| {
            query_pairs_of(raw)
                .into_iter()
                .find(|(key, _)| key == "ticket")
        })
        .map(|(_, value)| value)
    else {
        return failure(OAuthError::State);
    };
    // MUT:ticket-single-use — the ticket is spent here, once; a replayed
    // one finds nothing.
    // MUT:ticket-provider-before-spend — it is spent only on the provider
    // route it was minted for. A ticket presented on another provider's
    // route is refused WITHOUT being consumed: the check and the removal
    // are one step, so a wrong turn costs the browser nothing.
    let attempt = match app.auth.attempts.take_ticket_for(&ticket, &provider) {
        Ok((attempt, _purpose)) => attempt,
        Err(TicketRefusal::Mismatch) => return failure(OAuthError::MismatchProvider),
        Err(TicketRefusal::Unknown) => return failure(OAuthError::State),
    };
    let Some(binding) = attempt.browser_binding.clone() else {
        return failure(OAuthError::State);
    };
    let target = authorize_url(
        &built_in.metadata,
        &built_in.client,
        &redirect_uri,
        &attempt,
    );
    redirect(
        target.to_string(),
        vec![binding_cookie(&binding, 600, is_secure(&app))],
    )
}

/// `GET /api/auth/oauth/{provider}/callback?code&state` — the provider's
/// redirect back. Every exit is a redirect to a same-origin path: the
/// handoff code, the account page, or a closed-vocabulary reason.
async fn oauth_callback(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let query = callback_query(query.as_deref().unwrap_or_default());
    let binding = cookie_value(&headers, BINDING_COOKIE);
    let outcome = complete(&app, &provider, &query, binding.as_deref()).await;
    let location = match outcome {
        CallbackOutcome::Handoff { code } => format!("/login?handoff={code}"),
        CallbackOutcome::Linked { provider } => format!("/account?linked={provider}"),
        // MUT:closed-vocabulary — a failure names its reason from the enum;
        // nothing the provider said is ever echoed into a Location.
        CallbackOutcome::Failed { reason, link: true } => {
            format!("/account?oauth_error={}", reason.as_str())
        }
        CallbackOutcome::Failed {
            reason,
            link: false,
        } => format!("/login?oauth_error={}", reason.as_str()),
    };
    // The binding is spent with the attempt, whichever way this went.
    redirect(location, vec![binding_cookie("", 0, is_secure(&app))])
}

#[cfg(test)]
mod tests {
    use super::*;

    type Env = HashMap<&'static str, &'static str>;

    fn read(env: &Env) -> impl Fn(&str) -> Option<String> + '_ {
        move |name: &str| env.get(name).map(|value| (*value).to_owned())
    }

    fn github(env: &mut Env) {
        env.insert(GITHUB_CLIENT_ID_ENV, "cid-github");
        env.insert(GITHUB_CLIENT_SECRET_ENV, "s3cr3t-github");
        env.insert(PUBLIC_BASE_URL_ENV, "https://mail.example.test");
    }

    fn celestia(env: &mut Env) {
        env.insert(CELESTIA_CLIENT_ID_ENV, "cid-celestia");
        env.insert(CELESTIA_CLIENT_SECRET_ENV, "s3cr3t-celestia");
        env.insert(PUBLIC_BASE_URL_ENV, "https://mail.example.test");
    }

    // ── the catalog and the policy ──────────────────────────────────────

    #[test]
    fn no_variable_is_a_local_deployment() {
        let catalog = ProviderCatalog::from_env_with(read(&Env::new())).expect("empty env");
        assert!(catalog.providers.is_empty());
        assert!(catalog.public_base.is_none());
        assert_eq!(catalog.login_policy(), LoginPolicy::local());
        // MUT:local-needs-no-base — a bare public base URL alone must not
        // turn a password-only deployment into an error or into federated.
        let env = Env::from([(PUBLIC_BASE_URL_ENV, "https://mail.example.test")]);
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("base alone");
        assert!(catalog.providers.is_empty());
        assert_eq!(catalog.login_policy(), LoginPolicy::local());
    }

    #[test]
    fn both_providers_configure_in_display_order() {
        let mut env = Env::new();
        github(&mut env);
        env.insert(GOOGLE_CLIENT_ID_ENV, "cid-google");
        // No Google secret: a public client.
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        let ids: Vec<&str> = catalog.providers.iter().map(|p| p.id).collect();
        assert_eq!(ids, ["github", "google"]);
        assert!(matches!(
            catalog.provider("github").unwrap().client,
            ClientAuth::Confidential { .. }
        ));
        assert!(matches!(
            catalog.provider("google").unwrap().client,
            ClientAuth::Public { .. }
        ));
        assert_eq!(
            catalog.provider("github").unwrap().metadata.token_body,
            TokenBody::Json
        );
        assert_eq!(
            catalog.provider("google").unwrap().metadata.token_body,
            TokenBody::Form
        );
        assert_eq!(
            catalog.provider("github").unwrap().metadata.scopes,
            ["read:user", "user:email"]
        );
        assert_eq!(
            catalog
                .provider("github")
                .unwrap()
                .metadata
                .authorize_url
                .as_str(),
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(
            catalog
                .provider("github")
                .unwrap()
                .metadata
                .token_url
                .as_str(),
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(
            catalog
                .provider("github")
                .unwrap()
                .metadata
                .userinfo_url
                .as_ref()
                .map(Url::as_str),
            Some("https://api.github.com/user")
        );
        assert_eq!(
            catalog
                .provider("google")
                .unwrap()
                .metadata
                .issuer
                .as_deref(),
            Some("https://accounts.google.com")
        );
        assert_eq!(
            catalog.provider("google").unwrap().metadata.scopes,
            ["openid", "profile", "email"]
        );
        assert_eq!(
            catalog.redirect_uri("github").unwrap().as_str(),
            "https://mail.example.test/api/auth/oauth/github/callback"
        );
        assert_eq!(catalog.return_origins(), ["https://mail.example.test"]);
        // A blank secret is "no secret": a public client.
        let mut env = Env::new();
        github(&mut env);
        env.insert(GITHUB_CLIENT_SECRET_ENV, "   ");
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        assert!(matches!(
            catalog.provider("github").unwrap().client,
            ClientAuth::Public { .. }
        ));
    }

    // ── the family IdP (celestia) ───────────────────────────────────────

    #[test]
    fn the_family_idp_derives_its_endpoints_from_one_issuer() {
        // The three endpoints are the issuer's contract paths; each is
        // spelled in the preset and every one must sit under the same
        // origin as the issuer the identity is keyed on.
        assert_eq!(
            CELESTIA_AUTHORIZE_URL,
            format!("{CELESTIA_ISSUER}/oauth/authorize")
        );
        assert_eq!(
            CELESTIA_TOKEN_URL,
            format!("{CELESTIA_ISSUER}/api/oauth/token")
        );
        assert_eq!(
            CELESTIA_USERINFO_URL,
            format!("{CELESTIA_ISSUER}/api/oauth/userinfo")
        );
        assert_eq!(CELESTIA_ISSUER, "https://auth.celestia.world");

        let mut env = Env::new();
        celestia(&mut env);
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        let provider = catalog.provider("celestia").expect("configured");
        assert_eq!(
            provider.metadata.authorize_url.as_str(),
            CELESTIA_AUTHORIZE_URL
        );
        assert_eq!(provider.metadata.token_url.as_str(), CELESTIA_TOKEN_URL);
        assert_eq!(
            provider.metadata.userinfo_url.as_ref().map(Url::as_str),
            Some(CELESTIA_USERINFO_URL)
        );
        assert_eq!(provider.metadata.issuer.as_deref(), Some(CELESTIA_ISSUER));
        assert_eq!(provider.metadata.provider, "celestia");
        // A form token body: RFC 6749 §4.1.3, what the issuer accepts first.
        assert_eq!(provider.metadata.token_body, TokenBody::Form);
        assert_eq!(provider.metadata.scopes, ["openid", "profile", "email"]);
        assert_eq!(
            catalog.redirect_uri("celestia").unwrap().as_str(),
            "https://mail.example.test/api/auth/oauth/celestia/callback"
        );
    }

    #[test]
    fn the_family_idp_is_a_confidential_client_or_a_public_one() {
        // A configured secret: a confidential client, and the secret never
        // reaches a log line.
        let mut env = Env::new();
        celestia(&mut env);
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        assert!(matches!(
            catalog.provider("celestia").unwrap().client,
            ClientAuth::Confidential { .. }
        ));
        assert_eq!(
            catalog.provider("celestia").unwrap().client.client_secret(),
            Some("s3cr3t-celestia")
        );
        let shown = format!("{catalog:?}");
        assert!(!shown.contains("s3cr3t-celestia"), "{shown}");

        // No secret at all: REFUSED — erp's token endpoint validates the
        // client secret on every exchange (no public-client lane), so the
        // "public client" reading of an absent secret would 401 at the
        // first exchange. Unlike GitHub's, this preset is confidential or
        // it does not exist.
        let env = Env::from([
            (CELESTIA_CLIENT_ID_ENV, "cid-celestia"),
            (PUBLIC_BASE_URL_ENV, "https://mail.example.test"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(CELESTIA_CLIENT_SECRET_ENV))
        );

        // A blank secret is "no secret" too: the same refusal.
        let env = Env::from([
            (CELESTIA_CLIENT_ID_ENV, "cid-celestia"),
            (CELESTIA_CLIENT_SECRET_ENV, "   "),
            (PUBLIC_BASE_URL_ENV, "https://mail.example.test"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(CELESTIA_CLIENT_SECRET_ENV))
        );
    }

    #[test]
    fn the_family_idp_row_follows_its_client_id() {
        // MUT:celestia-row-needs-client-id — with no client id the row is
        // absent, exactly as for GitHub and Google: a deployment that
        // registers nothing renders no dead button.
        let env = Env::from([(PUBLIC_BASE_URL_ENV, "https://mail.example.test")]);
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        let policy = catalog.login_policy();
        assert!(policy.methods.is_empty(), "{policy:?}");
        assert!(catalog.provider("celestia").is_none());

        // Configured: one `oauth` row, labelled by id (the webui localises
        // it to "Celestia ID"), pointing at this host's start route.
        let mut env = Env::new();
        celestia(&mut env);
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        let policy = catalog.validated_login_policy().expect("policy");
        assert_eq!(policy.mode, AuthMode::Federated);
        assert!(policy.password);
        assert_eq!(
            serde_json::to_value(&policy).expect("json")["methods"][0],
            serde_json::json!({
                "kind": "oauth", "id": "celestia", "label": "celestia",
                "href": "/api/auth/oauth/celestia",
                "provider": "celestia"
            })
        );
    }

    #[test]
    fn the_family_idp_sits_after_the_generic_providers() {
        let mut env = Env::new();
        github(&mut env);
        env.insert(GOOGLE_CLIENT_ID_ENV, "cid-google");
        env.insert(CELESTIA_CLIENT_ID_ENV, "cid-celestia");
        env.insert(CELESTIA_CLIENT_SECRET_ENV, "s3cr3t-celestia");
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        let ids: Vec<&str> = catalog.providers.iter().map(|p| p.id).collect();
        assert_eq!(ids, ["github", "google", "celestia"]);
        // Every provider variable is listed, so a deployment can check its
        // own environment against the closed set.
        for name in [
            CELESTIA_CLIENT_ID_ENV,
            CELESTIA_CLIENT_SECRET_ENV,
            GITHUB_CLIENT_ID_ENV,
            GOOGLE_CLIENT_SECRET_ENV,
        ] {
            assert!(PROVIDER_ENV_VARS.contains(&name), "{name}");
        }
    }

    #[test]
    fn the_family_idp_requires_its_secret_no_public_lane() {
        // MUT:celestia-needs-secret — erp's token endpoint validates the
        // client secret on every exchange (no public-client lane), so an
        // id without a secret is a deployment that 401s at the first
        // exchange. Refused at startup, with the variable named.
        let env = Env::from([
            (CELESTIA_CLIENT_ID_ENV, "cid-celestia"),
            (PUBLIC_BASE_URL_ENV, "https://mail.example.test"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(CELESTIA_CLIENT_SECRET_ENV))
        );
        // The confidential row stays valid.
        let mut full = Env::new();
        celestia(&mut full);
        assert!(ProviderCatalog::from_env_with(read(&full)).is_ok());
    }

    #[test]
    fn the_family_idp_fails_closed_on_its_own_variables() {
        // A secret with no id names the id it needs.
        let env = Env::from([
            (CELESTIA_CLIENT_SECRET_ENV, "s3cr3t-celestia"),
            (PUBLIC_BASE_URL_ENV, "https://mail.example.test"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(CELESTIA_CLIENT_ID_ENV))
        );
        // A blank id is not "unconfigured" either.
        let env = Env::from([
            (CELESTIA_CLIENT_ID_ENV, "   "),
            (PUBLIC_BASE_URL_ENV, "https://mail.example.test"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(CELESTIA_CLIENT_ID_ENV))
        );
        // Configured without a secret: the family IdP preset is refused as
        // a whole (id + secret are one unit — erp has no public-client
        // lane), before the base URL is even considered.
        let env = Env::from([(CELESTIA_CLIENT_ID_ENV, "cid-celestia")]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(CELESTIA_CLIENT_SECRET_ENV))
        );
        // The same id WITH its secret: now the public base is what is
        // missing (an explicit env without the base — `celestia()` carries
        // it, so the base-missing case needs its own env here).
        let env = Env::from([
            (CELESTIA_CLIENT_ID_ENV, "cid-celestia"),
            (CELESTIA_CLIENT_SECRET_ENV, "s3cr3t-celestia"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(PUBLIC_BASE_URL_ENV))
        );
    }

    #[test]
    fn presence_fails_closed_on_an_incomplete_set() {
        // MUT:presence-not-content — a provider variable that is set but
        // blank means federated was intended; the rest must be complete.
        let env = Env::from([(GITHUB_CLIENT_ID_ENV, "cid-github")]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(PUBLIC_BASE_URL_ENV))
        );
        // A blank client id next to a present secret is not "no provider".
        let env = Env::from([(GITHUB_CLIENT_SECRET_ENV, "s3cr3t")]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(GITHUB_CLIENT_ID_ENV))
        );
        let env = Env::from([(GITHUB_CLIENT_ID_ENV, "   ")]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(GITHUB_CLIENT_ID_ENV))
        );
        // The base URL alone does not complete a provider.
        let env = Env::from([
            (GITHUB_CLIENT_SECRET_ENV, "s3cr3t"),
            (PUBLIC_BASE_URL_ENV, "https://mail.example.test"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(GITHUB_CLIENT_ID_ENV))
        );
        // Google's variable names its own missing pieces.
        let env = Env::from([(GOOGLE_CLIENT_ID_ENV, "cid")]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(PUBLIC_BASE_URL_ENV))
        );
        let env = Env::from([(GOOGLE_CLIENT_SECRET_ENV, "s3cr3t")]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).err(),
            Some(AuthConfigError::Missing(GOOGLE_CLIENT_ID_ENV))
        );
    }

    #[test]
    fn the_public_base_must_be_a_secure_bare_origin() {
        let parse = Url::parse("mail.example.test").unwrap_err();
        for (raw, expected) in [
            (
                "http://mail.example.test",
                AuthConfigError::NotHttps(PUBLIC_BASE_URL_ENV),
            ),
            (
                "mail.example.test",
                AuthConfigError::InvalidUrl(PUBLIC_BASE_URL_ENV, parse),
            ),
            (
                "https://mail.example.test/webmail",
                AuthConfigError::NotAnOrigin(PUBLIC_BASE_URL_ENV),
            ),
            (
                "https://mail.example.test?x=1",
                AuthConfigError::NotAnOrigin(PUBLIC_BASE_URL_ENV),
            ),
            (
                "https://mail.example.test#top",
                AuthConfigError::NotAnOrigin(PUBLIC_BASE_URL_ENV),
            ),
        ] {
            let env = Env::from([
                (GITHUB_CLIENT_ID_ENV, "cid-github"),
                (PUBLIC_BASE_URL_ENV, raw),
            ]);
            assert_eq!(
                ProviderCatalog::from_env_with(read(&env)).unwrap_err(),
                expected,
                "{raw:?}"
            );
        }
        // Loopback http is the one plain-http exception (a local rig).
        let env = Env::from([
            (GITHUB_CLIENT_ID_ENV, "cid"),
            (PUBLIC_BASE_URL_ENV, "http://127.0.0.1:3023"),
        ]);
        ProviderCatalog::from_env_with(read(&env)).expect("loopback http");
        // A malformed base URL is refused even with no provider beside it.
        let env = Env::from([(PUBLIC_BASE_URL_ENV, "http://mail.example.test")]);
        assert!(ProviderCatalog::from_env_with(read(&env)).is_err());
    }

    #[test]
    fn the_public_base_refuses_userinfo() {
        // MUT:no-userinfo — `https://user:password@host` is one authority
        // to the normalised `Url` and another to every other parser. It is
        // refused before anything else is judged, and the refusal names
        // the variable without echoing what was typed in front of the `@`.
        for raw in [
            "https://someone:s3cr3t@mail.example.test",
            "https://someone@mail.example.test",
            "https://:s3cr3t@mail.example.test",
            "https://@mail.example.test",
            "http://someone:s3cr3t@127.0.0.1:3023",
        ] {
            let env = Env::from([
                (GITHUB_CLIENT_ID_ENV, "cid-github"),
                (PUBLIC_BASE_URL_ENV, raw),
            ]);
            let refused = ProviderCatalog::from_env_with(read(&env)).unwrap_err();
            assert_eq!(
                refused,
                AuthConfigError::Userinfo(PUBLIC_BASE_URL_ENV),
                "{raw:?}"
            );
            let shown = refused.to_string();
            assert!(
                !shown.contains("s3cr3t") && !shown.contains("someone"),
                "{shown}"
            );
        }
        // An `@` after the authority is data, not an authority: not
        // userinfo (though a query is still not a bare origin).
        let env = Env::from([
            (GITHUB_CLIENT_ID_ENV, "cid-github"),
            (PUBLIC_BASE_URL_ENV, "https://mail.example.test/?to=a@b"),
        ]);
        assert_eq!(
            ProviderCatalog::from_env_with(read(&env)).unwrap_err(),
            AuthConfigError::NotAnOrigin(PUBLIC_BASE_URL_ENV)
        );
    }

    #[test]
    fn the_public_base_is_bare_on_the_raw_string() {
        // MUT:bare-origin-raw — the normalised `Url` folds each of these
        // onto a bare origin (`/.` and `/a/..` become `/`, a backslash is a
        // path separator, an embedded tab is dropped); the raw spelling is
        // what the operator wrote, and it carries more than an origin.
        assert_eq!(
            Url::parse("https://mail.example.test/.").unwrap().path(),
            "/"
        );
        for raw in [
            "https://mail.example.test/.",
            "https://mail.example.test/..",
            "https://mail.example.test/a/..",
            "https://mail.example.test//",
            "https://mail.example.test\\",
            "https://mail.example.test\\webmail",
            "https://mail.exa\tmple.test",
        ] {
            let env = Env::from([
                (GITHUB_CLIENT_ID_ENV, "cid-github"),
                (PUBLIC_BASE_URL_ENV, raw),
            ]);
            assert_eq!(
                ProviderCatalog::from_env_with(read(&env)).unwrap_err(),
                AuthConfigError::NotAnOrigin(PUBLIC_BASE_URL_ENV),
                "{raw:?}"
            );
        }
        // With and without the one optional slash: the same origin.
        for raw in ["https://mail.example.test", "https://mail.example.test/"] {
            let env = Env::from([
                (GITHUB_CLIENT_ID_ENV, "cid-github"),
                (PUBLIC_BASE_URL_ENV, raw),
            ]);
            let catalog = ProviderCatalog::from_env_with(read(&env)).expect("a bare origin");
            assert_eq!(catalog.return_origins(), ["https://mail.example.test"]);
        }
    }

    #[test]
    fn the_policy_validates_in_both_modes() {
        let local = ProviderCatalog::local()
            .validated_login_policy()
            .expect("local policy");
        assert_eq!(local.mode, AuthMode::Local);
        assert!(local.password);
        assert!(local.methods.is_empty());
        let json = serde_json::to_value(&local).expect("json");
        assert_eq!(
            json,
            serde_json::json!({ "version": 1, "mode": "local", "password": true, "methods": [] })
        );

        let mut env = Env::new();
        github(&mut env);
        env.insert(GOOGLE_CLIENT_ID_ENV, "cid-google");
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        let federated = catalog.validated_login_policy().expect("federated policy");
        assert_eq!(federated.mode, AuthMode::Federated);
        // MUT:password-stays — the mailbox password card stays offered beside
        // the providers; own-domain accounts prove it on the verify step.
        assert!(federated.password);
        let json = serde_json::to_value(&federated).expect("json");
        assert_eq!(
            json["methods"][0],
            serde_json::json!({
                "kind": "oauth", "id": "github", "label": "github",
                "href": "/api/auth/oauth/github", "provider": "github"
            })
        );
        assert_eq!(json["methods"][1]["provider"], "google");
        // The server picks no display language: the label is the id.
        assert_eq!(json["methods"][1]["label"], "google");
        assert_eq!(json["methods"][1]["href"], "/api/auth/oauth/google");
        assert!(json.get("relay").is_none());
    }

    #[test]
    fn debug_never_shows_a_secret() {
        let mut env = Env::new();
        github(&mut env);
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        let shown = format!("{catalog:?}");
        assert!(shown.contains("github"), "{shown}");
        // MUT:no-secret-in-debug — a logged catalog must not carry the
        // confidential client's secret.
        assert!(!shown.contains("s3cr3t-github"), "{shown}");
        let shown = format!("{:?}", AuthState::new(catalog, Arc::new(NoFetcher)));
        assert!(!shown.contains("s3cr3t-github"), "{shown}");
    }

    // ── links over the snapshot store ────────────────────────────────────

    fn temp_store(tag: &str) -> Arc<ayane_store::RedbStateStore> {
        let dir = std::env::temp_dir().join(format!("ayane-links-{tag}-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        Arc::new(ayane_store::RedbStateStore::open(dir.join("state.redb")).expect("store"))
    }

    /// Seed `addresses` as accounts (admin on the first one) and return
    /// their ids in order.
    fn seed(store: &ayane_store::RedbStateStore, addresses: &[&str]) -> Vec<uuid::Uuid> {
        let mut state = StoredState::empty();
        state.desired.domains.push(ayane_proto::MailDomain {
            name: "example.test".to_owned(),
            catch_all: None,
            enabled: true,
            dkim: None,
        });
        for (index, raw) in addresses.iter().enumerate() {
            state.desired.accounts.push(ayane_proto::Account {
                id: uuid::Uuid::new_v4(),
                address: Address::parse(raw).expect("address"),
                display_name: format!("Owner {index}"),
                quota_bytes: 0,
                admin: index == 0,
            });
        }
        state.desired.validate().expect("valid state");
        let ids = state
            .desired
            .accounts
            .iter()
            .map(|account| account.id)
            .collect();
        store.save(&state).expect("seed");
        ids
    }

    fn who(provider: &str, subject: &str) -> ExternalIdentity {
        ExternalIdentity::opaque(provider, subject)
    }

    #[tokio::test]
    async fn one_identity_belongs_to_one_account() {
        let store = temp_store("exclusive");
        let ids = seed(&store, &["alice@example.test", "bob@example.test"]);
        let links = IdentityLinks::new(store.clone());
        assert_eq!(
            links
                .find_user(&who("github", "sub-1"))
                .await
                .expect("lookup"),
            None
        );
        assert_eq!(
            links
                .link(&who("github", "sub-1"), ids[0])
                .await
                .expect("link"),
            LinkOutcome::Linked
        );
        // The same account again is idempotent.
        assert_eq!(
            links
                .link(&who("github", "sub-1"), ids[0])
                .await
                .expect("relink"),
            LinkOutcome::AlreadyLinked
        );
        // MUT:exclusive-link — a second account must never take the identity over.
        let refused = links
            .link(&who("github", "sub-1"), ids[1])
            .await
            .expect_err("second account must be refused");
        assert!(
            matches!(
                refused.downcast_ref::<KirinoError>(),
                Some(KirinoError::ConstraintViolation(_))
            ),
            "{refused}"
        );
        let linked = links
            .find_user(&who("github", "sub-1"))
            .await
            .expect("lookup")
            .expect("linked");
        assert_eq!(linked.user_id, ids[0]);
        assert_eq!(linked.identity.provider, "github");
        // Spellings that differ only by whitespace or issuer case are one key.
        let normalised = links
            .link(
                &ExternalIdentity {
                    provider: " github ".to_owned(),
                    issuer: None,
                    subject: "sub-1 ".to_owned(),
                },
                ids[1],
            )
            .await
            .expect_err("normalised key");
        assert!(
            matches!(
                normalised.downcast_ref::<KirinoError>(),
                Some(KirinoError::ConstraintViolation(prose))
                    if prose.contains("alice@example.test")
            ),
            "{normalised}"
        );
        // An unknown account is refused: nothing is written for it.
        assert!(links
            .link(&who("github", "sub-2"), uuid::Uuid::new_v4())
            .await
            .is_err());
        assert_eq!(
            links
                .find_user(&who("github", "sub-2"))
                .await
                .expect("lookup"),
            None
        );
    }

    #[tokio::test]
    async fn concurrent_links_of_one_identity_yield_exactly_one_winner() {
        // MUT:locked-link — the check and the write are one locked step;
        // without it, two racing links could both pass the check.
        let store = temp_store("race");
        let ids = seed(
            &store,
            &[
                "alice@example.test",
                "bob@example.test",
                "carol@example.test",
            ],
        );
        let mut joined = tokio::task::JoinSet::new();
        for id in &ids {
            let links = IdentityLinks::new(store.clone());
            let id = *id;
            joined.spawn(async move { links.link(&who("github", "sub-race"), id).await });
        }
        let mut linked = 0;
        let mut refused = 0;
        while let Some(result) = joined.join_next().await {
            match result.expect("task") {
                Ok(LinkOutcome::Linked) => linked += 1,
                Err(e)
                    if matches!(
                        e.downcast_ref::<KirinoError>(),
                        Some(KirinoError::ConstraintViolation(_))
                    ) =>
                {
                    refused += 1
                }
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        assert_eq!((linked, refused), (1, 2));
        assert_eq!(store.load().expect("load").external_identities.len(), 1);
    }

    #[tokio::test]
    async fn unlink_is_the_owners_and_is_always_allowed() {
        let store = temp_store("unlink");
        let ids = seed(&store, &["alice@example.test", "bob@example.test"]);
        let links = IdentityLinks::new(store.clone());
        links
            .link(&who("github", "sub-1"), ids[0])
            .await
            .expect("link");
        // A non-owner cannot remove it.
        assert!(!links
            .unlink(&who("github", "sub-1"), ids[1])
            .await
            .expect("non-owner"));
        assert!(links
            .find_user(&who("github", "sub-1"))
            .await
            .expect("lookup")
            .is_some());
        // MUT:unlink-always-allowed — the owner may unlink; an own-domain
        // account keeps its password, so nothing is "left without a way in".
        assert!(links
            .unlink(&who("github", "sub-1"), ids[0])
            .await
            .expect("owner"));
        assert_eq!(
            links
                .find_user(&who("github", "sub-1"))
                .await
                .expect("lookup"),
            None
        );
        assert!(!links
            .unlink(&who("github", "sub-1"), ids[0])
            .await
            .expect("gone"));
        // The link row is gone from the snapshot too.
        assert!(store.load().expect("load").external_identities.is_empty());
    }

    #[tokio::test]
    async fn list_and_record_follow_the_account() {
        let store = temp_store("list");
        let ids = seed(&store, &["alice@example.test", "bob@example.test"]);
        let links = IdentityLinks::new(store.clone());
        links
            .link(&who("github", "sub-1"), ids[0])
            .await
            .expect("link");
        links
            .link(&who("google", "sub-2"), ids[0])
            .await
            .expect("link");
        links
            .link(&who("github", "sub-3"), ids[1])
            .await
            .expect("link");
        let listed = links.list_for_user(ids[0]).await.expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].identity.provider, "github");
        assert_eq!(listed[0].identity.subject, "sub-1");
        assert_eq!(listed[1].identity.provider, "google");
        assert!(listed.iter().all(|link| link.last_login_at.is_none()));
        // A login through the link is recorded on that link only.
        links
            .record_login(&who("github", "sub-1"))
            .await
            .expect("record");
        // An unknown identity is a no-op.
        links
            .record_login(&who("github", "nobody"))
            .await
            .expect("no-op");
        let listed = links.list_for_user(ids[0]).await.expect("list");
        assert!(listed[0].last_login_at.is_some());
        assert!(listed[1].last_login_at.is_none());
        let bobs = links.list_for_user(ids[1]).await.expect("list");
        assert_eq!(bobs.len(), 1);
        assert!(bobs[0].last_login_at.is_none());
        assert_eq!(
            links
                .account_id_of(&Address::parse("bob@example.test").expect("address"))
                .expect("id"),
            ids[1]
        );
        assert!(matches!(
            links.account_id_of(&Address::parse("nobody@example.test").expect("address")),
            Err(AuthError::AccountMissing)
        ));
    }

    #[tokio::test]
    async fn an_orphaned_link_signs_nobody_in() {
        // A link whose account was removed answers "not linked": it is
        // never a way back into a re-created mailbox.
        let store = temp_store("orphan");
        let ids = seed(&store, &["alice@example.test"]);
        let links = IdentityLinks::new(store.clone());
        links
            .link(&who("github", "sub-1"), ids[0])
            .await
            .expect("link");
        let mut state = store.load().expect("load");
        state.desired.accounts.clear();
        store.save(&state).expect("save");
        assert_eq!(
            links
                .find_user(&who("github", "sub-1"))
                .await
                .expect("lookup"),
            None
        );
        // The stale id no longer resolves either.
        assert!(links.unlink(&who("github", "sub-1"), ids[0]).await.is_err());
    }

    #[tokio::test]
    async fn a_whole_state_replacement_keeps_the_links_of_surviving_accounts() {
        let store = temp_store("replace");
        let ids = seed(&store, &["alice@example.test", "bob@example.test"]);
        let links = IdentityLinks::new(store.clone());
        links
            .link(&who("github", "sub-1"), ids[0])
            .await
            .expect("link");
        links
            .link(&who("github", "sub-2"), ids[1])
            .await
            .expect("link");
        // The replacement keeps alice (new id) and drops bob.
        let mut replacement = StoredState::empty();
        replacement.desired = store.load().expect("load").desired;
        replacement.desired.accounts.truncate(1);
        replacement.desired.accounts[0].id = uuid::Uuid::new_v4();
        replacement.password_hashes = store.load().expect("load").password_hashes.clone();
        crate::api::replace_state(store.as_ref(), replacement).expect("replace");
        let state = store.load().expect("load");
        assert_eq!(state.external_identities.len(), 1);
        assert_eq!(state.external_identities[0].subject, "sub-1");
        assert_eq!(
            links
                .list_for_user(state.desired.accounts[0].id)
                .await
                .expect("list")
                .len(),
            1
        );
    }

    // ── in-flight sign-ins ───────────────────────────────────────────────

    #[tokio::test]
    async fn a_ticket_starts_exactly_one_attempt_and_it_is_bound() {
        let attempts = AttemptStore::new();
        let (ticket, attempt) = attempts
            .begin(
                "github",
                AttemptPurpose::Login {
                    return_to: Some("/inbox".to_owned()),
                },
            )
            .await
            .expect("begin");
        assert!(attempt.browser_binding.is_some(), "every attempt is bound");
        assert_eq!(attempt.provider, "github");
        // MUT:ticket-provider-before-spend — the ticket is spent only on
        // its own provider's route; a wrong provider is refused and the
        // ticket survives it, intact and still single-use.
        assert_eq!(
            attempts.take_ticket_for(&ticket, "google"),
            Err(TicketRefusal::Mismatch)
        );
        let (taken, purpose) = attempts
            .take_ticket_for(&ticket, "github")
            .expect("spend on the right route after the refusal");
        assert_eq!(taken.state, attempt.state);
        assert_eq!(
            purpose,
            AttemptPurpose::Login {
                return_to: Some("/inbox".to_owned())
            }
        );
        // MUT:ticket-single-use — a replayed ticket finds nothing.
        assert_eq!(
            attempts.take_ticket_for(&ticket, "github"),
            Err(TicketRefusal::Unknown)
        );
        assert_eq!(
            attempts.take_ticket_for("never-issued", "github"),
            Err(TicketRefusal::Unknown)
        );
        // kirino's store still holds the attempt for the callback.
        assert!(attempts
            .attempts
            .take(&attempt.state)
            .await
            .expect("take")
            .is_some());
    }

    #[tokio::test]
    async fn a_ticket_on_another_provider_is_refused_but_not_consumed() {
        let attempts = AttemptStore::new();
        let (ticket, attempt) = attempts
            .begin(
                "github",
                AttemptPurpose::Link {
                    address: Address::parse("a@example.test").expect("address"),
                },
            )
            .await
            .expect("begin");
        // A ticket presented with a provider the catalog does not know is
        // no mismatch at all — the route refuses it by name before any
        // lookup — and an unknown value is simply unknown.
        assert_eq!(
            attempts.take_ticket_for("no-such-ticket", "github"),
            Err(TicketRefusal::Unknown)
        );
        // Two refusals on the same ticket: it is still there afterwards.
        for _ in 0..2 {
            assert_eq!(
                attempts.take_ticket_for(&ticket, "google"),
                Err(TicketRefusal::Mismatch),
                "a refusal must not consume the ticket"
            );
        }
        let (taken, purpose) = attempts
            .take_ticket_for(&ticket, "github")
            .expect("the ticket outlived the refusals");
        assert_eq!(taken.state, attempt.state);
        assert_eq!(
            purpose,
            AttemptPurpose::Link {
                address: Address::parse("a@example.test").expect("address")
            }
        );
        // Spent once: dead.
        assert_eq!(
            attempts.take_ticket_for(&ticket, "github"),
            Err(TicketRefusal::Unknown)
        );
    }

    #[tokio::test]
    async fn the_purpose_rides_the_state_exactly_once() {
        let attempts = AttemptStore::new();
        let (_ticket, attempt) = attempts
            .begin(
                "google",
                AttemptPurpose::Link {
                    address: Address::parse("a@example.test").expect("address"),
                },
            )
            .await
            .expect("begin");
        assert!(attempts.take_purpose("unknown-state").is_none());
        assert_eq!(
            attempts.take_purpose(&attempt.state),
            Some(AttemptPurpose::Link {
                address: Address::parse("a@example.test").expect("address")
            })
        );
        assert!(attempts.take_purpose(&attempt.state).is_none());
    }

    /// The handoff a finished sign-in parks, as `sign_in` builds it.
    fn handoff() -> Handoff {
        Handoff::new(
            Address::parse("alice@example.test").expect("address"),
            "Alice".to_owned(),
            false,
            Some("cached-credential".to_owned()),
            Some("/inbox".to_owned()),
        )
    }

    #[test]
    fn a_handoff_is_claimed_exactly_once() {
        let attempts = AttemptStore::new();
        let code = attempts.park_handoff(handoff());
        // MUT:handoff-one-time — the code is a bearer for the session it
        // mints; a second claim must find nothing.
        let claimed = attempts.take_handoff(&code).expect("first claim");
        assert_eq!(claimed.address.as_str(), "alice@example.test");
        assert_eq!(claimed.credential.as_deref(), Some("cached-credential"));
        assert!(attempts.take_handoff(&code).is_none());
        assert!(attempts.take_handoff("never-parked").is_none());
        // Debug never shows a credential.
        let shown = format!("{claimed:?}");
        assert!(shown.contains("[redacted]"), "{shown}");
    }

    #[test]
    fn a_handoff_lives_for_the_handoff_ttl_and_no_longer() {
        // MUT:handoff-ttl — the one construction site stamps exactly one
        // minute: neither the ticket's ten minutes (the code is a bearer
        // for the session it mints) nor less. The minute is spelled out
        // here and NOT read from `HANDOFF_TTL`: an expectation that
        // follows the constant lets any other value pass with it. Parking
        // keeps the instant as stamped: it never re-stamps.
        const ONE_MINUTE: Duration = Duration::from_secs(60);
        let before = Instant::now();
        let handoff = handoff();
        let after = Instant::now();
        assert!(
            handoff.expires >= before + ONE_MINUTE,
            "the code dies too early: {:?} before {:?}",
            handoff.expires,
            before + ONE_MINUTE
        );
        assert!(
            handoff.expires <= after + ONE_MINUTE,
            "the code outlives its minute: {:?} after {:?}",
            handoff.expires,
            after + ONE_MINUTE
        );
        let attempts = AttemptStore::new();
        let code = attempts.park_handoff(handoff);
        let parked = attempts
            .take_handoff(&code)
            .expect("a fresh code is claimed");
        assert!(parked.expires >= before + ONE_MINUTE && parked.expires <= after + ONE_MINUTE);
    }

    #[test]
    fn an_expired_handoff_is_never_claimed() {
        // MUT:handoff-expiry — a code that outlived its minute is no code
        // at all: the claim answers nothing (no session is minted from
        // it), and the dead handoff is taken out on the way.
        const TWO_MINUTES: Duration = Duration::from_secs(120);
        let attempts = AttemptStore::new();
        let now = Instant::now();
        // Longer ago than any code may live; on a monotonic clock that
        // does not reach back that far (a machine up for under two
        // minutes) any past instant is as expired.
        let long_gone = now
            .checked_sub(TWO_MINUTES)
            .or_else(|| now.checked_sub(Duration::from_secs(1)))
            .expect("the monotonic clock reaches back a second");
        let code = attempts.park_handoff(Handoff {
            expires: long_gone,
            ..handoff()
        });
        assert!(attempts.take_handoff(&code).is_none());
        assert!(
            !attempts
                .handoffs
                .lock()
                .expect("handoffs mutex")
                .contains_key(&code),
            "the expired handoff is removed, not left for a later claim"
        );
        assert!(attempts.take_handoff(&code).is_none());
        // A live one parked beside it is untouched by that refusal.
        let live = attempts.park_handoff(handoff());
        assert!(attempts.take_handoff(&live).is_some());
    }

    #[test]
    fn return_addresses_stay_on_this_origin() {
        let mut env = Env::new();
        github(&mut env);
        let catalog = ProviderCatalog::from_env_with(read(&env)).expect("catalog");
        assert_eq!(
            safe_return_to(&catalog, Some("/inbox?box=Sent")),
            Some("/inbox?box=Sent".to_owned())
        );
        assert_eq!(
            safe_return_to(&catalog, Some("https://mail.example.test/inbox")),
            Some("/inbox".to_owned())
        );
        // MUT:return-same-origin — a foreign origin, a scheme-relative path
        // and the bare root are dropped, never forwarded.
        for bad in [
            "https://evil.example/inbox",
            "//evil.example/inbox",
            "/\\evil.example",
            "/",
            "",
            "inbox",
        ] {
            assert_eq!(safe_return_to(&catalog, Some(bad)), None, "{bad:?}");
        }
        assert_eq!(safe_return_to(&catalog, None), None);
        // Without a public base nothing absolute is accepted; a path still is.
        assert_eq!(
            safe_return_to(&ProviderCatalog::local(), Some("/inbox")),
            Some("/inbox".to_owned())
        );
        assert_eq!(
            safe_return_to(
                &ProviderCatalog::local(),
                Some("https://mail.example.test/inbox")
            ),
            None
        );
    }

    #[test]
    fn the_error_vocabulary_is_closed_on_the_wire() {
        let every = [
            OAuthError::Denied,
            OAuthError::State,
            OAuthError::Code,
            OAuthError::Binding,
            OAuthError::MismatchProvider,
            OAuthError::Token,
            OAuthError::Identity,
            OAuthError::Unreachable,
            OAuthError::UnknownProvider,
            OAuthError::NotConfigured,
            OAuthError::Unlinked,
            OAuthError::AlreadyLinked,
            OAuthError::LinkFailed,
            OAuthError::Store,
        ];
        for reason in every {
            assert_eq!(
                serde_json::to_value(reason).expect("json"),
                Value::String(reason.as_str().to_owned())
            );
        }
        // Every kirino problem maps onto one of them.
        assert_eq!(
            OAuthError::from(CallbackProblem::BindingMismatch),
            OAuthError::Binding
        );
        assert_eq!(
            OAuthError::from(CallbackProblem::UnknownState),
            OAuthError::State
        );
        assert_eq!(
            OAuthError::from(CallbackProblem::Transport("x".to_owned())),
            OAuthError::Unreachable
        );
        assert_eq!(
            OAuthError::from(CallbackProblem::ProviderDenied {
                error: "access_denied".to_owned(),
                description: Some("user denied".to_owned())
            }),
            OAuthError::Denied
        );
    }
}
