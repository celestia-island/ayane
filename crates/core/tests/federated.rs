//! Federated sign-in end to end, without a provider: the browser routes
//! (discovery, start, callback) under `tower::oneshot`, the RPC surface
//! through the test seam, and kirino's `HttpFetcher` replaced by a scripted
//! transport. The protocol (PKCE, state, token exchange) is kirino's; what
//! is pinned here is ayane's policy around it — binding, single use, the
//! purpose of an attempt, link-only first sign-in, the locked session (the
//! mailbox password as the account's second factor) and the locked
//! snapshot writes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use kirino::auth::identity::external::{ExternalIdentity, ExternalIdentityStore};
use kirino::auth::passport::oauth::HttpFetcher;
use serde_json::{json, Value};
use tower::ServiceExt;
use url::Url;

use ayane::auth::{
    AuthState, IdentityLinks, ProviderCatalog, GITHUB_CLIENT_ID_ENV, GOOGLE_CLIENT_ID_ENV,
    PUBLIC_BASE_URL_ENV,
};
use ayane::rpc::WsContext;
use ayane::state::AppState;
use ayane::transport::RpcSurface;
use ayane_store::{
    password, ExternalLink, RedbStateStore, StateStore, StoreError, StoredState, Template,
};

const PASSWORD: &str = "correct-horse-battery";
const ADMIN: &str = "admin-secret-token";
const BASE: &str = "https://mail.example.test";
/// GitHub's subject the scripted provider answers with.
const SUBJECT: u64 = 12345;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ayane-federated-{tag}-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The provider, scripted: one access token, one subject.
#[derive(Default)]
struct Scripted {
    subject: AtomicU64,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl HttpFetcher for Scripted {
    async fn post_form(&self, url: &Url, params: &[(&str, &str)]) -> anyhow::Result<Value> {
        let fields: HashMap<&str, &str> = params.iter().copied().collect();
        // The token request kirino builds spends the PKCE verifier.
        assert!(fields.get("code_verifier").is_some_and(|v| v.len() >= 43));
        assert_eq!(fields.get("grant_type"), Some(&"authorization_code"));
        self.calls
            .lock()
            .expect("calls")
            .push(format!("form {}", url.path()));
        Ok(json!({ "access_token": "at-scripted", "token_type": "Bearer" }))
    }

    async fn post_json(&self, url: &Url, body: &Value) -> anyhow::Result<Value> {
        assert!(body["code_verifier"]
            .as_str()
            .is_some_and(|v| v.len() >= 43));
        assert!(
            body.get("client_secret").is_none(),
            "a public client sends no secret"
        );
        self.calls
            .lock()
            .expect("calls")
            .push(format!("json {}", url.path()));
        Ok(json!({ "access_token": "at-scripted", "token_type": "Bearer" }))
    }

    async fn get_bearer(&self, url: &Url, access_token: &str) -> anyhow::Result<Value> {
        assert_eq!(url.as_str(), "https://api.github.com/user");
        assert_eq!(access_token, "at-scripted");
        self.calls
            .lock()
            .expect("calls")
            .push("bearer /user".to_owned());
        Ok(json!({
            "id": self.subject.load(Ordering::SeqCst),
            "login": "octocat",
            "name": "The Octocat",
        }))
    }
}

struct Fixture {
    app: Router,
    surface: RpcSurface,
    store: Arc<RedbStateStore>,
    http: Arc<Scripted>,
    _root: PathBuf,
}

/// The fixture with GitHub as a public client and no other provider.
fn fixture(tag: &str) -> Fixture {
    fixture_with(tag, false)
}

/// The fixture: GitHub as a public client, plus Google (a public client
/// too) when `google` is set — the two-provider deployment the
/// wrong-route refusals need, since a route only exists for a configured
/// provider.
fn fixture_with(tag: &str, google: bool) -> Fixture {
    let root = temp_dir(tag);
    let store = Arc::new(RedbStateStore::open(root.join("store.redb")).expect("store"));
    let mk = |raw: &str, admin: bool| ayane_proto::Account {
        id: uuid::Uuid::new_v4(),
        address: ayane_proto::Address::parse(raw).expect("address"),
        display_name: raw.split('@').next().unwrap_or(raw).to_owned(),
        quota_bytes: 0,
        admin,
    };
    let alice = mk("alice@example.test", true);
    let bob = mk("bob@example.test", false);
    let mut hashes = HashMap::new();
    for account in [&alice, &bob] {
        hashes.insert(
            account.address.to_string(),
            password::hash_password(PASSWORD).expect("hash"),
        );
    }
    store
        .save(&StoredState {
            desired: ayane_proto::DesiredState {
                domains: vec![ayane_proto::MailDomain {
                    name: "example.test".to_owned(),
                    catch_all: None,
                    enabled: true,
                    dkim: None,
                }],
                accounts: vec![alice, bob],
                ..Default::default()
            },
            password_hashes: hashes,
            external_identities: Vec::new(),
        })
        .expect("seed");
    let config = ayane::config::Config {
        listen: "127.0.0.1:3023".parse().expect("listen"),
        log_filter: String::new(),
        state_dir: root.join("state"),
        admin_token: Some(ADMIN.to_owned()),
        compose_file: root.join("docker-compose.yml"),
        imap: "127.0.0.1:1".to_owned(),
        submission: "127.0.0.1:1".to_owned(),
        cert_file: None,
    };
    // GitHub as a public client; Google only when asked for.
    let catalog = ProviderCatalog::from_env_with(|name| match name {
        GITHUB_CLIENT_ID_ENV => Some("cid-github".to_owned()),
        GOOGLE_CLIENT_ID_ENV if google => Some("cid-google".to_owned()),
        PUBLIC_BASE_URL_ENV => Some(BASE.to_owned()),
        _ => None,
    })
    .expect("catalog");
    let http = Arc::new(Scripted {
        subject: AtomicU64::new(SUBJECT),
        calls: Mutex::new(Vec::new()),
    });
    let app = AppState {
        store: store.clone(),
        driver: Arc::new(ayane::driver::RecordingDriver::new(
            root.join("docker-compose.yml"),
        )),
        config: Arc::new(config),
        auth: Arc::new(AuthState::new(catalog, http.clone())),
    };
    let surface = RpcSurface {
        app: app.clone(),
        sessions: Arc::new(ayane::session::SessionStore::new()),
    };
    let router = ayane::api::full_router(surface.clone());
    Fixture {
        app: router,
        surface,
        store,
        http,
        _root: root,
    }
}

/// One call on a fresh, unauthenticated connection.
async fn call(surface: &RpcSurface, method: &str, params: Value) -> Value {
    call_on(surface, &mut WsContext::new(), method, params).await
}

/// One call on `ctx` — a connection that may already carry a session.
async fn call_on(surface: &RpcSurface, ctx: &mut WsContext, method: &str, params: Value) -> Value {
    let text = ayane::transport::handle_one_for_tests(
        surface,
        ctx,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string(),
    )
    .await
    .expect("reply");
    serde_json::from_str(&text).expect("json")
}

/// `GET uri` with at most one extra header.
async fn request_with(
    app: &Router,
    uri: &str,
    header: Option<(&str, String)>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().uri(uri);
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, headers, body.to_vec())
}

async fn request(
    app: &Router,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    request_with(app, uri, cookie.map(|value| ("cookie", value.to_owned()))).await
}

/// `GET /api/v1/state` carrying one credential header: the status alone.
async fn rest_status(app: &Router, header: &'static str, value: String) -> StatusCode {
    request_with(app, "/api/v1/state", Some((header, value)))
        .await
        .0
}

fn location(headers: &HeaderMap) -> String {
    headers
        .get("location")
        .expect("a redirect")
        .to_str()
        .expect("location")
        .to_owned()
}

fn query_value(url: &str, key: &str) -> Option<String> {
    let parsed = Url::parse(url).expect("url");
    parsed
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// The `ayane_oauth_binding` cookie the start route set (its raw value).
fn binding_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("ayane_oauth_binding="))
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .split_once('=')
                .map(|(_, v)| v.to_owned())
                .unwrap_or_default()
        })
        .filter(|value| !value.is_empty())
}

/// `session.oauthBegin` alone: the `href` it answers (ticket unspent).
async fn begin(fx: &Fixture, params: Value) -> String {
    let begun = call(&fx.surface, "session.oauthBegin", params).await;
    begun["result"]["href"]
        .as_str()
        .unwrap_or_else(|| panic!("{begun}"))
        .to_owned()
}

/// `GET href`: spend the ticket; the authorize redirect's `Location` and
/// the binding cookie value the browser now holds.
async fn navigate(fx: &Fixture, href: &str) -> (String, String) {
    let (status, headers, _) = request(&fx.app, href, None).await;
    assert_eq!(status, StatusCode::FOUND);
    let target = location(&headers);
    assert!(
        target.starts_with("https://github.com/login/oauth/authorize?"),
        "{target}"
    );
    // The authorization request carries PKCE and the redirect, never a secret.
    for pair in [
        "code_challenge_method=S256",
        "code_challenge=",
        "state=",
        "client_id=cid-github",
    ] {
        assert!(target.contains(pair), "{target} lacks {pair}");
    }
    assert!(
        target.contains(&format!(
            "redirect_uri={}",
            urlencode(&format!("{BASE}/api/auth/oauth/github/callback"))
        )),
        "{target}"
    );
    let binding = binding_of(&headers).expect("the start route sets the binding cookie");
    (target, binding)
}

/// `session.oauthBegin` → `GET href`: the href, the authorize redirect's
/// `Location` and the binding cookie value.
async fn start(fx: &Fixture, params: Value) -> (String, String, String) {
    let href = begin(fx, params).await;
    assert!(href.starts_with("/api/auth/oauth/github?ticket="), "{href}");
    let (target, binding) = navigate(fx, &href).await;
    (href, target, binding)
}

/// The provider's redirect back, for the `state` of an authorize redirect,
/// sent with `cookie` (the raw binding value; `None` = no cookie).
async fn callback(fx: &Fixture, authorize: &str, query: &str, cookie: Option<&str>) -> String {
    let state = query_value(authorize, "state").expect("state in the authorize URL");
    let uri = format!("/api/auth/oauth/github/callback?{query}&state={state}");
    let header = cookie.map(|value| format!("ayane_oauth_binding={value}"));
    let (_, headers, _) = request(&fx.app, &uri, header.as_deref()).await;
    location(&headers)
}

/// Drive one attempt from `session.oauthBegin` to the callback with the
/// browser that started it; the callback's `Location`.
async fn round_trip(fx: &Fixture, params: Value, query: &str) -> String {
    let (_, authorize, binding) = start(fx, params).await;
    callback(fx, &authorize, query, Some(&binding)).await
}

/// Percent-encoding the way `url` writes a query value (enough for a URL).
fn urlencode(raw: &str) -> String {
    Url::parse_with_params("http://x/", [("r", raw)])
        .expect("url")
        .query()
        .and_then(|q| q.strip_prefix("r="))
        .unwrap_or_default()
        .to_owned()
}

fn cookie_flags(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn the_discovery_document_names_the_configured_providers() {
    let fx = fixture("discovery");
    let (status, _, body) = request(&fx.app, "/api/auth/login-methods", None).await;
    assert_eq!(status, StatusCode::OK);
    let policy: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(policy["mode"], "federated");
    assert_eq!(policy["password"], true);
    assert_eq!(policy["methods"][0]["provider"], "github");
    assert_eq!(policy["methods"][0]["href"], "/api/auth/oauth/github");
    assert_eq!(policy["methods"].as_array().expect("list").len(), 1);
    // The RPC answers the same document.
    let reply = call(&fx.surface, "session.loginPolicy", json!({})).await;
    assert_eq!(reply["result"], policy);
}

#[tokio::test]
async fn a_ticket_starts_exactly_one_attempt() {
    // Two providers, so that "another provider's route" is a route that
    // exists: the refusal below is the ticket's mismatch, not an unknown
    // provider.
    let fx = fixture_with("ticket", true);
    let (href, _, binding) = start(&fx, json!({ "provider": "github" })).await;
    assert!(!binding.is_empty());
    // MUT:ticket-single-use — the href is spent; a second navigation of
    // the very same URL never reaches the provider again.
    let (status, headers, _) = request(&fx.app, &href, None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
    assert!(binding_of(&headers).is_none(), "no new binding is issued");

    // MUT:ticket-provider-before-spend — a ticket minted for GitHub and
    // presented on Google's route is refused BY NAME and is NOT consumed:
    // the same wrong turn can be taken twice and cost the browser nothing.
    let href = begin(&fx, json!({ "provider": "github" })).await;
    let ticket = href.split("ticket=").nth(1).expect("ticket").to_owned();
    for _ in 0..2 {
        let (status, headers, _) = request(
            &fx.app,
            &format!("/api/auth/oauth/google?ticket={ticket}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location(&headers), "/login?oauth_error=mismatch_provider");
        assert!(
            binding_of(&headers).is_none(),
            "no binding is issued on a refusal"
        );
    }
    // The ticket outlives the refusals: on ITS provider's route it still
    // starts the attempt…
    navigate(&fx, &href).await;
    // …exactly once: after that one successful use the ticket is dead.
    let (status, headers, _) = request(&fx.app, &href, None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
    assert!(binding_of(&headers).is_none());

    // No ticket at all reads the same way.
    let (status, headers, _) = request(&fx.app, "/api/auth/oauth/github", None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
    // An unknown provider is refused by name, and before anything is
    // spent: a real ticket in that request is still good afterwards.
    let href = begin(&fx, json!({ "provider": "github" })).await;
    let ticket = href.split("ticket=").nth(1).expect("ticket").to_owned();
    let (status, headers, _) = request(
        &fx.app,
        &format!("/api/auth/oauth/gitlab?ticket={ticket}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=unknown_provider");
    assert!(binding_of(&headers).is_none());
    navigate(&fx, &href).await;
}

#[tokio::test]
async fn oauth_begin_is_a_sign_in_whatever_token_is_around() {
    let fx = fixture("purpose");
    // The connection is authenticated as bob…
    let mut ctx = WsContext::new();
    let login = call_on(
        &fx.surface,
        &mut ctx,
        "session.login",
        json!({ "address": "bob@example.test", "password": PASSWORD }),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    // MUT:oauth-begin-always-login — the purpose is the method's. A session
    // on the connection, or a token in the params, must not turn
    // `session.oauthBegin` into a link for that mailbox: an attempt started
    // here is a sign-in, lands on the login page, and stores no link.
    for params in [
        json!({ "provider": "github" }),
        json!({ "provider": "github", "token": token }),
    ] {
        let begun = call_on(&fx.surface, &mut ctx, "session.oauthBegin", params.clone()).await;
        let href = begun["result"]["href"]
            .as_str()
            .unwrap_or_else(|| panic!("{begun}"));
        let (authorize, binding) = navigate(&fx, href).await;
        let landed = callback(&fx, &authorize, "code=code-1", Some(&binding)).await;
        assert_eq!(landed, "/login?oauth_error=unlinked", "{params}");
    }
    assert!(fx
        .store
        .load()
        .expect("load")
        .external_identities
        .is_empty());
    // Linking is the authenticated method's, and only that.
    let linked = call_on(
        &fx.surface,
        &mut ctx,
        "session.linkIdentity",
        json!({ "provider": "github" }),
    )
    .await;
    let href = linked["result"]["href"]
        .as_str()
        .unwrap_or_else(|| panic!("{linked}"));
    let (authorize, binding) = navigate(&fx, href).await;
    let landed = callback(&fx, &authorize, "code=code-1", Some(&binding)).await;
    assert_eq!(landed, "/account?linked=github");
    let links = fx.store.load().expect("load").external_identities;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].address.as_str(), "bob@example.test");
}

#[tokio::test]
async fn the_binding_cookie_is_http_only_lax_scoped_and_secure() {
    let fx = fixture("cookie");
    let begun = call(
        &fx.surface,
        "session.oauthBegin",
        json!({ "provider": "github" }),
    )
    .await;
    let href = begun["result"]["href"].as_str().expect("href").to_owned();
    let (_, headers, _) = request(&fx.app, &href, None).await;
    let set = cookie_flags(&headers);
    assert_eq!(set.len(), 1, "{set:?}");
    let cookie = &set[0];
    // MUT:binding-cookie-flags — the binding must be unreachable from
    // script (HttpOnly), scoped to the OAuth routes, short-lived, and
    // Secure because the public base URL is https.
    for flag in [
        "HttpOnly",
        "SameSite=Lax",
        "Path=/api/auth/oauth",
        "Max-Age=600",
        "Secure",
    ] {
        assert!(cookie.contains(flag), "{cookie} lacks {flag}");
    }
}

#[tokio::test]
async fn the_callback_requires_the_browser_that_started_the_attempt() {
    let fx = fixture("binding");
    // MUT:binding-required — without the binding cookie the callback is
    // refused BEFORE any token is exchanged.
    let (_, authorize, _) = start(&fx, json!({ "provider": "github" })).await;
    let target = callback(&fx, &authorize, "code=code-1", None).await;
    assert_eq!(target, "/login?oauth_error=binding");
    assert!(
        fx.http.calls.lock().expect("calls").is_empty(),
        "no token was exchanged"
    );

    // Mismatched cookie: same refusal, still no exchange.
    let (_, authorize, _) = start(&fx, json!({ "provider": "github" })).await;
    let target = callback(&fx, &authorize, "code=code-1", Some("not-the-binding")).await;
    assert_eq!(target, "/login?oauth_error=binding");
    assert!(fx.http.calls.lock().expect("calls").is_empty());

    // MUT:binding-per-attempt — another attempt's binding is a mismatch too.
    let (_, first, first_binding) = start(&fx, json!({ "provider": "github" })).await;
    let (_, second, second_binding) = start(&fx, json!({ "provider": "github" })).await;
    let target = callback(&fx, &first, "code=code-1", Some(&second_binding)).await;
    assert_eq!(target, "/login?oauth_error=binding");
    // The attempt a wrong browser presented is spent with the refusal: its
    // own browser cannot pick it up afterwards either (fail closed).
    let target = callback(&fx, &first, "code=code-1", Some(&first_binding)).await;
    assert_eq!(target, "/login?oauth_error=state");
    assert!(fx.http.calls.lock().expect("calls").is_empty());
    // The other attempt was never presented and still works for its browser.
    let target = callback(&fx, &second, "code=code-1", Some(&second_binding)).await;
    assert_eq!(target, "/login?oauth_error=unlinked");
    assert_eq!(fx.http.calls.lock().expect("calls").len(), 2);
}

#[tokio::test]
async fn an_unlinked_identity_signs_nobody_in() {
    let fx = fixture("unlinked");
    let target = round_trip(&fx, json!({ "provider": "github" }), "code=code-1").await;
    // MUT:link-only-first-sign-in — no mailbox exists for this identity
    // and none is created: the SPA gets a closed reason, nothing else.
    assert_eq!(target, "/login?oauth_error=unlinked");
    assert!(
        !target.contains("handoff="),
        "no handoff for an unlinked identity"
    );
    let state = fx.store.load().expect("load");
    assert!(state.external_identities.is_empty());
    assert_eq!(
        state.desired.accounts.len(),
        2,
        "no mailbox was provisioned"
    );
}

#[tokio::test]
async fn a_linked_identity_hands_off_into_a_locked_session() {
    let fx = fixture("linked");
    let links = IdentityLinks::new(fx.store.clone());
    let alice = fx.store.load().expect("load").desired.accounts[0].id;
    links
        .link(
            &ExternalIdentity::opaque("github", SUBJECT.to_string()),
            alice,
        )
        .await
        .expect("pre-link");

    let (_, authorize, binding) = start(
        &fx,
        json!({ "provider": "github", "returnTo": "/inbox?box=Sent" }),
    )
    .await;
    let state = query_value(&authorize, "state").expect("state");
    let uri = format!("/api/auth/oauth/github/callback?code=code-1&state={state}");
    let (status, headers, _) = request(
        &fx.app,
        &uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let target = location(&headers);
    assert!(target.starts_with("/login?handoff="), "{target}");
    // No token ever rides a URL: the handoff is a one-time code.
    assert!(
        !target.contains("at-scripted") && !target.contains("token="),
        "{target}"
    );
    // The binding cookie is cleared on the way out.
    let cleared = cookie_flags(&headers);
    assert!(
        cleared.iter().any(|c| c.contains("Max-Age=0")),
        "{cleared:?}"
    );
    let code = target.split("handoff=").nth(1).expect("code").to_owned();

    // Nothing can claim it over the RPC before the SPA does — and the
    // claim is one-time.
    let claim = call(&fx.surface, "session.claimHandoff", json!({ "code": code })).await;
    let result = &claim["result"];
    assert_eq!(result["address"], "alice@example.test");
    assert_eq!(result["needs_mailbox_password"], true);
    assert_eq!(result["return_to"], "/inbox?box=Sent");
    // `admin` is the authority the session HOLDS: none while the mailbox
    // is locked, though alice's account is an administrator (the full
    // probe is `a_locked_provider_session_administers_nothing_until_the_mailbox_password_is_proven`).
    assert_eq!(result["admin"], false);
    let token = result["token"].as_str().expect("token").to_owned();
    assert_eq!(token.len(), 64, "a 32-byte session token in hex");
    // MUT:handoff-one-time — the code is spent.
    let again = call(&fx.surface, "session.claimHandoff", json!({ "code": code })).await;
    assert_eq!(
        again["error"]["message"],
        "Session.HandoffInvalid: the sign-in handoff is unknown, spent or expired"
    );

    // Mail refuses while the mailbox is locked.
    let mail = call(&fx.surface, "mail.list", json!({ "token": token })).await;
    // MUT:mail-locked — the provider proved the identity, not the mailbox.
    assert_eq!(
        mail["error"]["message"],
        "Session.MailboxLocked: the mailbox is locked: enter the mailbox password"
    );
    let star = call(
        &fx.surface,
        "mail.star",
        json!({ "token": token, "uid": 1 }),
    )
    .await;
    assert!(star["error"]["message"]
        .as_str()
        .unwrap_or("")
        .starts_with("Session.MailboxLocked:"));
    let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
    assert_eq!(who["result"]["needs_mailbox_password"], true);

    // A wrong password is refused and leaves the session locked.
    let wrong = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "token": token, "password": "nope" }),
    )
    .await;
    assert_eq!(
        wrong["error"]["message"],
        "Session.InvalidCredentials: mailbox password is wrong"
    );
    let mail = call(&fx.surface, "mail.list", json!({ "token": token })).await;
    assert!(mail["error"]["message"]
        .as_str()
        .unwrap_or("")
        .starts_with("Session.MailboxLocked:"));

    // The right one unlocks: mail now reaches the (absent) IMAP leg.
    let unlocked = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "token": token, "password": PASSWORD }),
    )
    .await;
    assert_eq!(unlocked["result"]["ok"], true);
    // Unlocked, the administrator's authority is the session's again.
    let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
    assert_eq!(who["result"]["admin"], true);
    assert_eq!(who["result"]["needs_mailbox_password"], false);
    let mail = call(&fx.surface, "mail.list", json!({ "token": token })).await;
    assert!(
        mail["error"]["message"]
            .as_str()
            .unwrap_or("")
            .starts_with("Mail.ImapFailed:"),
        "{}",
        mail
    );
    // Nothing left to unlock.
    let again = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "token": token, "password": PASSWORD }),
    )
    .await;
    assert_eq!(
        again["error"]["message"],
        "Session.MailboxNotLocked: this session owes no mailbox password"
    );

    // The sign-in through the link was recorded.
    let listed = links.list_for_user(alice).await.expect("list");
    assert!(listed[0].last_login_at.is_some());
}

#[tokio::test]
async fn a_foreign_return_address_is_dropped_and_a_same_origin_one_kept() {
    let fx = fixture("return");
    let links = IdentityLinks::new(fx.store.clone());
    let alice = fx.store.load().expect("load").desired.accounts[0].id;
    links
        .link(
            &ExternalIdentity::opaque("github", SUBJECT.to_string()),
            alice,
        )
        .await
        .expect("pre-link");
    for (asked, expected) in [
        ("https://evil.example/inbox", Value::Null),
        ("/inbox", json!("/inbox")),
    ] {
        let begun = call(
            &fx.surface,
            "session.oauthBegin",
            json!({ "provider": "github", "returnTo": asked }),
        )
        .await;
        let href = begun["result"]["href"].as_str().expect("href").to_owned();
        let (_, headers, _) = request(&fx.app, &href, None).await;
        let binding = binding_of(&headers).expect("binding");
        let target = location(&headers);
        let state = query_value(&target, "state").expect("state");
        let uri = format!("/api/auth/oauth/github/callback?code=c&state={state}");
        let (_, headers, _) = request(
            &fx.app,
            &uri,
            Some(&format!("ayane_oauth_binding={binding}")),
        )
        .await;
        let code = location(&headers)
            .split("handoff=")
            .nth(1)
            .expect("handoff")
            .to_owned();
        let claim = call(&fx.surface, "session.claimHandoff", json!({ "code": code })).await;
        assert_eq!(claim["result"]["return_to"], expected, "{asked}");
    }
}

#[tokio::test]
async fn a_link_sign_in_stores_the_identity_for_the_authenticated_mailbox() {
    let fx = fixture("link");
    // bob signs in with his password…
    let login = call(
        &fx.surface,
        "session.login",
        json!({ "address": "bob@example.test", "password": PASSWORD }),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    // …and links GitHub from the account page.
    let begun = call(
        &fx.surface,
        "session.linkIdentity",
        json!({ "token": token, "provider": "github" }),
    )
    .await;
    let href = begun["result"]["href"].as_str().expect("href").to_owned();
    let (_, headers, _) = request(&fx.app, &href, None).await;
    let binding = binding_of(&headers).expect("binding");
    let state = query_value(&location(&headers), "state").expect("state");
    let uri = format!("/api/auth/oauth/github/callback?code=c&state={state}");
    let (status, headers, _) = request(
        &fx.app,
        &uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    // MUT:link-purpose — the callback knows (from the state) that this
    // attempt was a link, and lands on the account page, not the login.
    assert_eq!(location(&headers), "/account?linked=github");
    let state = fx.store.load().expect("load");
    assert_eq!(state.external_identities.len(), 1);
    assert_eq!(
        state.external_identities[0].address.as_str(),
        "bob@example.test"
    );
    assert_eq!(state.external_identities[0].subject, SUBJECT.to_string());

    // Listed for bob, absent for alice; unlink removes it.
    let listed = call(&fx.surface, "session.identities", json!({ "token": token })).await;
    assert_eq!(listed["result"]["identities"][0]["provider"], "github");
    let alice = call(
        &fx.surface,
        "session.login",
        json!({ "address": "alice@example.test", "password": PASSWORD }),
    )
    .await;
    let alice_token = alice["result"]["token"].as_str().expect("token").to_owned();
    let hers = call(
        &fx.surface,
        "session.identities",
        json!({ "token": alice_token }),
    )
    .await;
    assert_eq!(hers["result"]["identities"], json!([]));

    // alice cannot take the identity over: it is bob's.
    let begun = call(
        &fx.surface,
        "session.linkIdentity",
        json!({ "token": alice_token, "provider": "github" }),
    )
    .await;
    let href = begun["result"]["href"].as_str().expect("href").to_owned();
    let (_, headers, _) = request(&fx.app, &href, None).await;
    let binding = binding_of(&headers).expect("binding");
    let state = query_value(&location(&headers), "state").expect("state");
    let uri = format!("/api/auth/oauth/github/callback?code=c&state={state}");
    let (status, headers, _) = request(
        &fx.app,
        &uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    // MUT:one-identity-one-account — refused, and the link stays bob's.
    assert_eq!(location(&headers), "/account?oauth_error=already_linked");
    let state = fx.store.load().expect("load");
    assert_eq!(state.external_identities.len(), 1);
    assert_eq!(
        state.external_identities[0].address.as_str(),
        "bob@example.test"
    );

    let removed = call(
        &fx.surface,
        "session.unlinkIdentity",
        json!({ "token": token, "provider": "github" }),
    )
    .await;
    assert_eq!(removed["result"]["removed"], true);
    assert!(fx
        .store
        .load()
        .expect("load")
        .external_identities
        .is_empty());
    // Now alice may link it.
    let begun = call(
        &fx.surface,
        "session.linkIdentity",
        json!({ "token": alice_token, "provider": "github" }),
    )
    .await;
    let href = begun["result"]["href"].as_str().expect("href").to_owned();
    let (_, headers, _) = request(&fx.app, &href, None).await;
    let binding = binding_of(&headers).expect("binding");
    let state = query_value(&location(&headers), "state").expect("state");
    let uri = format!("/api/auth/oauth/github/callback?code=c&state={state}");
    let (status, headers, _) = request(
        &fx.app,
        &uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/account?linked=github");
    let links = IdentityLinks::new(fx.store.clone());
    assert_eq!(
        links
            .find_user(&ExternalIdentity::opaque("github", SUBJECT.to_string()))
            .await
            .expect("lookup")
            .expect("linked")
            .identity,
        ExternalIdentity::opaque("github", SUBJECT.to_string())
    );
}

#[tokio::test]
async fn linking_requires_a_session_and_offered_providers() {
    let fx = fixture("gates");
    let anonymous = call(
        &fx.surface,
        "session.linkIdentity",
        json!({ "provider": "github" }),
    )
    .await;
    assert_eq!(
        anonymous["error"]["message"],
        "Session.Required: login first"
    );
    let listed = call(&fx.surface, "session.identities", json!({})).await;
    assert_eq!(listed["error"]["message"], "Session.Required: login first");
    let login = call(
        &fx.surface,
        "session.login",
        json!({ "address": "bob@example.test", "password": PASSWORD }),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token");
    // Only the configured providers can start; the rest never reach a ticket.
    let unknown = call(
        &fx.surface,
        "session.linkIdentity",
        json!({ "token": token, "provider": "google" }),
    )
    .await;
    assert_eq!(
        unknown["error"]["message"],
        "Session.OAuthProviderUnknown: provider google is not offered here"
    );
    let unknown = call(
        &fx.surface,
        "session.oauthBegin",
        json!({ "provider": "gitlab" }),
    )
    .await;
    assert!(unknown["error"]["message"]
        .as_str()
        .unwrap_or("")
        .starts_with("Session.OAuthProviderUnknown:"));
    // A never-issued handoff mints nothing.
    let bogus = call(
        &fx.surface,
        "session.claimHandoff",
        json!({ "code": "made-up" }),
    )
    .await;
    assert!(bogus["error"]["message"]
        .as_str()
        .unwrap_or("")
        .starts_with("Session.HandoffInvalid:"));
}

#[tokio::test]
async fn a_provider_outage_is_a_closed_reason() {
    let fx = fixture("outage");
    // A subject the provider never yields for a real account still maps
    // onto the protocol: here the scripted provider simply works, so the
    // failure is upstream of it — an unknown state.
    let (_, authorize, binding) = start(&fx, json!({ "provider": "github" })).await;
    let state = query_value(&authorize, "state").expect("state");
    // Replays with a state that was never issued → closed reason, no prose.
    let uri = "/api/auth/oauth/github/callback?code=code-1&state=never-issued";
    let (status, headers, _) = request(
        &fx.app,
        uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
    assert!(fx.http.calls.lock().expect("calls").is_empty());
    // The real state still works afterwards (the binding matches).
    let uri = format!("/api/auth/oauth/github/callback?code=code-1&state={state}");
    let (status, headers, _) = request(
        &fx.app,
        &uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=unlinked");
    // A provider-side denial is a closed reason too.
    let (_, authorize, binding) = start(&fx, json!({ "provider": "github" })).await;
    let state = query_value(&authorize, "state").expect("state");
    let uri = format!("/api/auth/oauth/github/callback?error=access_denied&error_description=user+denied+token+xyz&state={state}");
    let (status, headers, _) = request(
        &fx.app,
        &uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=denied");
    // …and the provider's prose is never echoed into the Location.
    assert!(!location(&headers).contains("token+xyz"));
}

#[tokio::test]
async fn link_errors_go_back_to_the_account_page() {
    let fx = fixture("link-errors");
    // A link attempt whose account vanished between begin and callback.
    let login = call(
        &fx.surface,
        "session.login",
        json!({ "address": "bob@example.test", "password": PASSWORD }),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    let begun = call(
        &fx.surface,
        "session.linkIdentity",
        json!({ "token": token, "provider": "github" }),
    )
    .await;
    let href = begun["result"]["href"].as_str().expect("href").to_owned();
    let (_, headers, _) = request(&fx.app, &href, None).await;
    let binding = binding_of(&headers).expect("binding");
    let state = query_value(&location(&headers), "state").expect("state");
    let mut stored = fx.store.load().expect("load");
    stored
        .desired
        .accounts
        .retain(|account| account.address.as_str() != "bob@example.test");
    fx.store.save(&stored).expect("save");
    let uri = format!("/api/auth/oauth/github/callback?code=c&state={state}");
    let (status, headers, _) = request(
        &fx.app,
        &uri,
        Some(&format!("ayane_oauth_binding={binding}")),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/account?oauth_error=link_failed");
    // Nothing was written for the vanished account.
    assert!(fx
        .store
        .load()
        .expect("load")
        .external_identities
        .is_empty());
}

// ── the mailbox password as the account's second factor ─────────────────

#[tokio::test]
async fn a_locked_provider_session_administers_nothing_until_the_mailbox_password_is_proven() {
    let fx = fixture("locked-admin");
    // alice administers the service and links GitHub.
    let links = IdentityLinks::new(fx.store.clone());
    let alice = fx.store.load().expect("load").desired.accounts[0].id;
    links
        .link(
            &ExternalIdentity::opaque("github", SUBJECT.to_string()),
            alice,
        )
        .await
        .expect("pre-link");
    let landed = round_trip(&fx, json!({ "provider": "github" }), "code=code-1").await;
    let code = landed
        .strip_prefix("/login?handoff=")
        .unwrap_or_else(|| panic!("{landed}"))
        .to_owned();
    let claim = call(&fx.surface, "session.claimHandoff", json!({ "code": code })).await;
    let token = claim["result"]["token"].as_str().expect("token").to_owned();
    assert_eq!(claim["result"]["address"], "alice@example.test");
    assert_eq!(claim["result"]["needs_mailbox_password"], true);

    // MUT:locked-no-admin — the provider proved who the visitor is, and
    // that is the first factor only. While the mailbox password is owed,
    // every privileged surface refuses with the mail methods' own words —
    // a read, and three writes — though the account is an administrator.
    let locked = "Session.MailboxLocked: the mailbox is locked: enter the mailbox password";
    let probes: [(&str, Value); 4] = [
        ("admin.state.get", json!({})),
        (
            "admin.policy.put",
            json!({ "allowlist": [], "denylist": ["spam@example.org"] }),
        ),
        (
            "admin.accounts.setAdmin",
            json!({ "address": "bob@example.test", "admin": true }),
        ),
        ("admin.mcp.put", json!({ "tools": ["state.get"] })),
    ];
    for (method, params) in &probes {
        let mut params = params.clone();
        params["token"] = json!(token);
        let reply = call(&fx.surface, method, params).await;
        assert_eq!(reply["error"]["message"], locked, "{method}");
        assert!(reply.get("result").is_none(), "{method}: {reply}");
    }
    // Nothing was written behind the refusals.
    let stored = fx.store.load().expect("load");
    assert!(!stored
        .desired
        .accounts
        .iter()
        .any(|account| account.address.as_str() == "bob@example.test" && account.admin));
    assert!(stored.desired.policy.denylist.is_empty());
    assert!(stored.desired.mcp.tools.is_empty());
    // The flag the SPA gates on reports the authority held, not the grant.
    let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
    assert_eq!(who["result"]["admin"], false);
    assert_eq!(who["result"]["needs_mailbox_password"], true);

    // MUT:rest-token-only — the REST management face is gated on the
    // configured admin token alone (its middleware never consults the
    // session store): a session token opens nothing there, locked or not.
    for (header, value) in [
        ("x-admin-token", token.clone()),
        ("authorization", format!("Bearer {token}")),
    ] {
        let status = rest_status(&fx.app, header, value).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{header}");
    }

    // The second factor: the mailbox password, proven once.
    let unlocked = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "token": token, "password": PASSWORD }),
    )
    .await;
    assert_eq!(unlocked["result"]["ok"], true);
    for (method, params) in &probes {
        let mut params = params.clone();
        params["token"] = json!(token);
        let reply = call(&fx.surface, method, params).await;
        assert!(reply.get("error").is_none(), "{method}: {reply}");
    }
    let stored = fx.store.load().expect("load");
    assert_eq!(stored.desired.accounts.len(), 2);
    assert!(stored
        .desired
        .accounts
        .iter()
        .any(|account| account.address.as_str() == "bob@example.test" && account.admin));
    assert_eq!(stored.desired.policy.denylist.len(), 1);
    assert_eq!(stored.desired.mcp.tools, ["state.get"]);
    let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
    assert_eq!(who["result"]["admin"], true);
    assert_eq!(who["result"]["needs_mailbox_password"], false);
    // Unlocked or not, the REST face still takes the admin token only.
    let status = rest_status(&fx.app, "x-admin-token", token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let status = rest_status(&fx.app, "x-admin-token", ADMIN.to_owned()).await;
    assert_eq!(status, StatusCode::OK);
}

// ── the second factor is the session's own ──────────────────────────────

/// The account id of `address` in the fixture's store.
fn account_id(fx: &Fixture, address: &str) -> uuid::Uuid {
    fx.store
        .load()
        .expect("load")
        .desired
        .accounts
        .iter()
        .find(|account| account.address.as_str() == address)
        .expect("account")
        .id
}

/// `address` signs in through the provider: its identity (`subject`) is
/// linked, the round trip runs, the handoff is claimed. The session token
/// — LOCKED, the mailbox password still owed.
async fn locked_provider_session(fx: &Fixture, address: &str, subject: u64) -> String {
    IdentityLinks::new(fx.store.clone())
        .link(
            &ExternalIdentity::opaque("github", subject.to_string()),
            account_id(fx, address),
        )
        .await
        .expect("pre-link");
    fx.http.subject.store(subject, Ordering::SeqCst);
    let landed = round_trip(fx, json!({ "provider": "github" }), "code=code-1").await;
    let code = landed
        .strip_prefix("/login?handoff=")
        .unwrap_or_else(|| panic!("{landed}"))
        .to_owned();
    let claim = call(&fx.surface, "session.claimHandoff", json!({ "code": code })).await;
    assert_eq!(claim["result"]["address"], address, "{claim}");
    assert_eq!(claim["result"]["needs_mailbox_password"], true, "{claim}");
    claim["result"]["token"].as_str().expect("token").to_owned()
}

/// Whether `address` is an administrator in the store, set and saved.
fn set_admin(fx: &Fixture, address: &str, admin: bool) {
    let mut stored = fx.store.load().expect("load");
    stored
        .desired
        .accounts
        .iter_mut()
        .find(|account| account.address.as_str() == address)
        .expect("account")
        .admin = admin;
    fx.store.save(&stored).expect("save");
}

/// The provider's redirect back for a link attempt started by
/// `session.linkIdentity`: the `Location` the browser lands on.
async fn link_round_trip(fx: &Fixture, href: &str) -> String {
    let (authorize, binding) = navigate(fx, href).await;
    callback(fx, &authorize, "code=code-1", Some(&binding)).await
}

#[tokio::test]
async fn the_mailbox_password_is_proven_for_the_sessions_own_address() {
    const BOB_PASSWORD: &str = "bob-keeps-a-password-of-his-own";
    let fx = fixture("own-address");
    // Bob's password is his own: the two mailboxes share no secret.
    let mut stored = fx.store.load().expect("load");
    stored.password_hashes.insert(
        "bob@example.test".to_owned(),
        password::hash_password(BOB_PASSWORD).expect("hash"),
    );
    fx.store.save(&stored).expect("save");
    let alice = locked_provider_session(&fx, "alice@example.test", SUBJECT).await;
    let bob = locked_provider_session(&fx, "bob@example.test", 678).await;
    let refused = "Session.InvalidCredentials: mailbox password is wrong";

    // MUT:unlock-own-address — the password is verified against the hash
    // of the SESSION's own mailbox and of no other. Bob's CORRECT password
    // — naming his address or not — opens nothing on alice's session, and
    // alice's opens nothing on bob's; each answers exactly what a wrong
    // password answers, with no hint that another address was involved.
    for params in [
        json!({ "token": alice, "password": BOB_PASSWORD }),
        json!({ "token": alice, "password": BOB_PASSWORD, "address": "bob@example.test" }),
        json!({ "token": bob, "password": PASSWORD }),
        json!({ "token": bob, "password": PASSWORD, "address": "alice@example.test" }),
        json!({ "token": alice, "password": "nope" }),
    ] {
        let reply = call(&fx.surface, "session.unlockMailbox", params.clone()).await;
        assert_eq!(reply["error"]["message"], refused, "{params}");
        assert!(reply.get("result").is_none(), "{params}: {reply}");
    }
    // Both sessions are exactly as locked as before, and still their own.
    for (token, address) in [(&alice, "alice@example.test"), (&bob, "bob@example.test")] {
        let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
        assert_eq!(who["result"]["address"], address);
        assert_eq!(who["result"]["needs_mailbox_password"], true, "{address}");
    }
    let mail = call(&fx.surface, "mail.list", json!({ "token": alice })).await;
    assert!(mail["error"]["message"]
        .as_str()
        .unwrap_or("")
        .starts_with("Session.MailboxLocked:"));

    // The dispatcher reads the two fields by name and in the same order
    // as before: a missing password is malformed before any session is
    // consulted, and a password alone has no session to prove anything of.
    let reply = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "token": alice }),
    )
    .await;
    assert_eq!(
        reply["error"]["message"],
        "Session.MalformedParams: password is required"
    );
    let reply = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "password": "x" }),
    )
    .await;
    assert_eq!(reply["error"]["message"], "Session.Required: login first");

    // Each mailbox's own password opens its own session, and only it.
    for (token, address, own) in [
        (&alice, "alice@example.test", PASSWORD),
        (&bob, "bob@example.test", BOB_PASSWORD),
    ] {
        let unlocked = call(
            &fx.surface,
            "session.unlockMailbox",
            json!({ "token": token, "password": own }),
        )
        .await;
        assert_eq!(unlocked["result"]["ok"], true, "{address}: {unlocked}");
        assert_eq!(unlocked["result"]["address"], address);
        let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
        assert_eq!(who["result"]["needs_mailbox_password"], false, "{address}");
    }
}

#[tokio::test]
async fn every_session_reply_reports_the_authority_the_session_holds() {
    let fx = fixture("authority-held");
    // alice administers the service and links GitHub.
    let links = IdentityLinks::new(fx.store.clone());
    links
        .link(
            &ExternalIdentity::opaque("github", SUBJECT.to_string()),
            account_id(&fx, "alice@example.test"),
        )
        .await
        .expect("pre-link");
    let landed = round_trip(&fx, json!({ "provider": "github" }), "code=code-1").await;
    let code = landed
        .strip_prefix("/login?handoff=")
        .unwrap_or_else(|| panic!("{landed}"))
        .to_owned();
    // The callback recorded alice as an administrator. Her grant is then
    // withdrawn while the handoff waits: every reply from here on must
    // read the authority LIVE.
    set_admin(&fx, "alice@example.test", false);
    let claim = call(&fx.surface, "session.claimHandoff", json!({ "code": code })).await;
    let token = claim["result"]["token"].as_str().expect("token").to_owned();
    // MUT:whoami-authority-held — `admin` is the authority the session
    // HOLDS, as `sessions.is_admin` reads it: none while the mailbox
    // password is owed, and afterwards the live account table's answer —
    // never the flag as it stood when the session was minted. The same
    // in `claimHandoff`, `whoami` and the reply of the unlock itself.
    assert_eq!(claim["result"]["admin"], false, "{claim}");
    assert_eq!(claim["result"]["needs_mailbox_password"], true);
    let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
    assert_eq!(who["result"]["admin"], false);

    let unlocked = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "token": token, "password": PASSWORD }),
    )
    .await;
    assert_eq!(unlocked["result"]["ok"], true, "{unlocked}");
    // The record minted with the session says administrator; the unlock
    // bought none of it back.
    assert_eq!(unlocked["result"]["admin"], false, "{unlocked}");
    let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
    assert_eq!(who["result"]["admin"], false);
    assert_eq!(who["result"]["needs_mailbox_password"], false);

    // Granted again, the next reply already carries it.
    set_admin(&fx, "alice@example.test", true);
    let who = call(&fx.surface, "session.whoami", json!({ "token": token })).await;
    assert_eq!(who["result"]["admin"], true);
}

#[tokio::test]
async fn oauth_begin_ignores_an_address_in_the_params() {
    let fx = fixture("begin-address");
    // alice is linked; bob is signed in with his password, so a token of
    // his lies around too.
    let links = IdentityLinks::new(fx.store.clone());
    links
        .link(
            &ExternalIdentity::opaque("github", SUBJECT.to_string()),
            account_id(&fx, "alice@example.test"),
        )
        .await
        .expect("pre-link");
    let login = call(
        &fx.surface,
        "session.login",
        json!({ "address": "bob@example.test", "password": PASSWORD }),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    let only_alices = |fx: &Fixture| {
        let links = fx.store.load().expect("load").external_identities;
        assert_eq!(links.len(), 1, "{links:?}");
        assert_eq!(links[0].address.as_str(), "alice@example.test");
        assert_eq!(links[0].subject, SUBJECT.to_string());
    };

    // MUT:oauth-begin-no-address-channel — an `address` in the params
    // names no mailbox: the ticket is a sign-in's, whatever else rides
    // along. Completed, it signs the identity's LINKED mailbox in (alice)
    // — it never links the identity to the address it was handed (bob) —
    // and stores nothing.
    for params in [
        json!({ "provider": "github", "address": "bob@example.test" }),
        json!({ "provider": "github", "address": "bob@example.test", "token": token }),
    ] {
        let landed = round_trip(&fx, params.clone(), "code=code-1").await;
        assert!(landed.starts_with("/login?handoff="), "{params}: {landed}");
        let code = landed.split("handoff=").nth(1).expect("handoff").to_owned();
        let claim = call(&fx.surface, "session.claimHandoff", json!({ "code": code })).await;
        assert_eq!(
            claim["result"]["address"], "alice@example.test",
            "{params}: {claim}"
        );
        assert_eq!(claim["result"]["needs_mailbox_password"], true);
        only_alices(&fx);
    }

    // Nobody linked (another subject at the provider): the same params
    // are still a sign-in — refused as unlinked, never turned into a link
    // for the address they name.
    fx.http.subject.store(999, Ordering::SeqCst);
    let landed = round_trip(
        &fx,
        json!({ "provider": "github", "address": "bob@example.test", "token": token }),
        "code=code-1",
    )
    .await;
    assert_eq!(landed, "/login?oauth_error=unlinked");
    only_alices(&fx);
    // …and the address is not required either: the method's own params.
    let begun = call(
        &fx.surface,
        "session.oauthBegin",
        json!({ "provider": "github", "returnTo": "/inbox" }),
    )
    .await;
    assert!(begun["result"]["href"]
        .as_str()
        .unwrap_or("")
        .starts_with("/api/auth/oauth/github?ticket="));
    let begun = call(&fx.surface, "session.oauthBegin", json!({})).await;
    assert_eq!(
        begun["error"]["message"],
        "Session.MalformedParams: provider is required"
    );
}

#[tokio::test]
async fn a_locked_provider_session_cannot_change_its_linked_sign_ins() {
    let fx = fixture("locked-links");
    // alice signed in through GitHub: the one link is what let her in,
    // and her session owes the mailbox password.
    let token = locked_provider_session(&fx, "alice@example.test", SUBJECT).await;
    let locked = "Session.MailboxLocked: the mailbox is locked: enter the mailbox password";

    // MUT:locked-no-link-changes — the mailbox password is the account's
    // second factor for changing its ways in, exactly as for admin: while
    // it is owed, neither linking nor unlinking runs.
    for method in ["session.linkIdentity", "session.unlinkIdentity"] {
        let reply = call(
            &fx.surface,
            method,
            json!({ "token": token, "provider": "github" }),
        )
        .await;
        assert_eq!(reply["error"]["message"], locked, "{method}");
        assert!(reply.get("result").is_none(), "{method}: {reply}");
    }
    // Nothing moved: the link is alice's still.
    let links = fx.store.load().expect("load").external_identities;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].address.as_str(), "alice@example.test");
    // Listing is a read; the locked mailbox can still see what is linked.
    let listed = call(&fx.surface, "session.identities", json!({ "token": token })).await;
    assert_eq!(listed["result"]["identities"][0]["provider"], "github");

    // The second factor: the mailbox password, proven once.
    let unlocked = call(
        &fx.surface,
        "session.unlockMailbox",
        json!({ "token": token, "password": PASSWORD }),
    )
    .await;
    assert_eq!(unlocked["result"]["ok"], true, "{unlocked}");
    // Unlinked…
    let removed = call(
        &fx.surface,
        "session.unlinkIdentity",
        json!({ "token": token, "provider": "github" }),
    )
    .await;
    assert_eq!(removed["result"]["removed"], true, "{removed}");
    assert!(fx
        .store
        .load()
        .expect("load")
        .external_identities
        .is_empty());
    // …and linked again, the whole way to the provider and back.
    let begun = call(
        &fx.surface,
        "session.linkIdentity",
        json!({ "token": token, "provider": "github" }),
    )
    .await;
    let href = begun["result"]["href"]
        .as_str()
        .unwrap_or_else(|| panic!("{begun}"))
        .to_owned();
    let landed = link_round_trip(&fx, &href).await;
    assert_eq!(landed, "/account?linked=github");
    let links = fx.store.load().expect("load").external_identities;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].address.as_str(), "alice@example.test");
}

// ── slice writes under the store's lock ──────────────────────────────────

/// A store that lands a prepared link in the real store at the moment of
/// the next write it is asked for — an unlocked `save` or a locked
/// `update`. For a handler that `load`ed earlier, an unlocked `save` thus
/// overwrites a link that committed in between (the lost update); a
/// locked `update` finds it already there and keeps it.
struct Interleaving {
    inner: Arc<RedbStateStore>,
    /// Links to commit just before the next write.
    incoming: Mutex<Vec<ExternalLink>>,
}

impl Interleaving {
    fn land(&self) {
        let incoming = std::mem::take(&mut *self.incoming.lock().expect("incoming"));
        if incoming.is_empty() {
            return;
        }
        self.inner
            .update(&mut |state| {
                state.external_identities.extend(incoming.iter().cloned());
                Ok(())
            })
            .expect("land the link");
    }
}

impl StateStore for Interleaving {
    fn load(&self) -> Result<StoredState, StoreError> {
        self.inner.load()
    }

    fn save(&self, state: &StoredState) -> Result<(), StoreError> {
        self.land();
        self.inner.save(state)
    }

    fn update(
        &self,
        edit: &mut dyn FnMut(&mut StoredState) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        self.land();
        self.inner.update(edit)
    }

    fn list_templates(&self, owner: &str) -> Result<Vec<Template>, StoreError> {
        self.inner.list_templates(owner)
    }

    fn save_template(&self, template: &Template) -> Result<(), StoreError> {
        self.inner.save_template(template)
    }

    fn delete_template(&self, owner: &str, id: &str) -> Result<(), StoreError> {
        self.inner.delete_template(owner, id)
    }

    fn shared_imap_password(&self, address: &str) -> Result<String, StoreError> {
        self.inner.shared_imap_password(address)
    }
}

#[tokio::test]
async fn admin_slice_writes_do_not_drop_a_link_committed_meanwhile() {
    // MUT:locked-admin-write — `admin.accounts.setAdmin`, `admin.policy.put`
    // and `admin.mcp.put` edit the snapshot through the store's locked
    // read-modify-write. Each one below runs while a link commits: the
    // handler's own change AND the link must both come out of it. An
    // unlocked `load` → edit → `save` writes back the snapshot from before
    // the link and the link is gone.
    let mut fx = fixture("lost-link");
    let interleave = Arc::new(Interleaving {
        inner: fx.store.clone(),
        incoming: Mutex::new(Vec::new()),
    });
    fx.surface = RpcSurface {
        app: AppState {
            store: interleave.clone(),
            ..fx.surface.app.clone()
        },
        sessions: fx.surface.sessions.clone(),
    };
    fx.app = ayane::api::full_router(fx.surface.clone());
    let login = call(
        &fx.surface,
        "session.login",
        json!({ "address": "alice@example.test", "password": PASSWORD }),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();

    let link = |n: usize| ExternalLink {
        provider: "github".to_owned(),
        issuer: None,
        subject: format!("sub-{n}"),
        address: ayane_proto::Address::parse("alice@example.test").expect("address"),
        // The row's timestamp, read from JSON: the field's type is the
        // store's own (the one kirino's contract carries), so this test
        // declares no dependency of its own and consults no clock.
        created_at: serde_json::from_value(json!("2026-11-01T00:00:00Z")).expect("timestamp"),
        last_login_at: None,
    };
    type Edit = (&'static str, Value, fn(&StoredState) -> bool);
    let edits: [Edit; 3] =
        [
            (
                "admin.accounts.setAdmin",
                json!({ "address": "bob@example.test", "admin": true }),
                |stored| {
                    stored.desired.accounts.iter().any(|account| {
                        account.address.as_str() == "bob@example.test" && account.admin
                    })
                },
            ),
            (
                "admin.policy.put",
                json!({ "allowlist": [], "denylist": ["spam@example.org"] }),
                |stored| !stored.desired.policy.denylist.is_empty(),
            ),
            (
                "admin.mcp.put",
                json!({ "tools": ["state.get"] }),
                |stored| stored.desired.mcp.tools == ["state.get"],
            ),
        ];
    for (index, (method, mut params, took)) in edits.into_iter().enumerate() {
        interleave
            .incoming
            .lock()
            .expect("incoming")
            .push(link(index));
        params["token"] = json!(token);
        let reply = call(&fx.surface, method, params).await;
        assert_eq!(reply["result"]["saved"], true, "{method}: {reply}");
        let stored = fx.store.load().expect("load");
        assert!(took(&stored), "{method}: its own change must persist");
        assert!(
            stored.external_identities.iter().any(|row| {
                row.subject == format!("sub-{index}")
                    && row.address.as_str() == "alice@example.test"
            }),
            "{method} dropped the link committed meanwhile: {:?}",
            stored.external_identities
        );
    }
    // All three links and all three edits, together, in one snapshot.
    let stored = fx.store.load().expect("load");
    assert_eq!(stored.external_identities.len(), 3);
    // The refusals keep the lock discipline too: a rule that fails writes
    // nothing — here the link committed meanwhile survives a refused edit.
    interleave.incoming.lock().expect("incoming").push(link(9));
    let refused = call(
        &fx.surface,
        "admin.accounts.setAdmin",
        json!({ "token": token, "address": "nobody@example.test", "admin": true }),
    )
    .await;
    assert_eq!(
        refused["error"]["message"],
        "Admin.MalformedState: no such account"
    );
    let stored = fx.store.load().expect("load");
    assert_eq!(stored.external_identities.len(), 4);
    assert!(!stored
        .desired
        .accounts
        .iter()
        .any(|account| account.address.as_str() == "nobody@example.test"));
}
