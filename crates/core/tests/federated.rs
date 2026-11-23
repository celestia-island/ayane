//! Federated sign-in end to end, without a provider: the browser routes
//! (discovery, start, callback) under `tower::oneshot`, the RPC surface
//! through the test seam, and kirino's `HttpFetcher` replaced by a scripted
//! transport. The protocol (PKCE, state, token exchange) is kirino's; what
//! is pinned here is ayane's policy around it — binding, single use,
//! link-only first sign-in, the locked session and the mailbox password.

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
    AuthState, IdentityLinks, ProviderCatalog, GITHUB_CLIENT_ID_ENV, PUBLIC_BASE_URL_ENV,
};
use ayane::state::AppState;
use ayane::transport::RpcSurface;
use ayane_store::{password, RedbStateStore, StateStore, StoredState};

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

fn fixture(tag: &str) -> Fixture {
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
    // GitHub as a public client; no Google.
    let catalog = ProviderCatalog::from_env_with(|name| match name {
        GITHUB_CLIENT_ID_ENV => Some("cid-github".to_owned()),
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

async fn call(surface: &RpcSurface, method: &str, params: Value) -> Value {
    let mut ctx = ayane::rpc::WsContext::new();
    let text = ayane::transport::handle_one_for_tests(
        surface,
        &mut ctx,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string(),
    )
    .await
    .expect("reply");
    serde_json::from_str(&text).expect("json")
}

async fn request(
    app: &Router,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
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
    let fx = fixture("ticket");
    let (href, _, binding) = start(&fx, json!({ "provider": "github", "token": null })).await;
    assert!(!binding.is_empty());
    // MUT:ticket-single-use — the href is spent; a second navigation of
    // the very same URL never reaches the provider again.
    let (status, headers, _) = request(&fx.app, &href, None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
    assert!(binding_of(&headers).is_none(), "no new binding is issued");
    // A ticket minted for another provider's route is refused and spent.
    let href = begin(&fx, json!({ "provider": "github", "token": null })).await;
    let ticket = href.split("ticket=").nth(1).expect("ticket").to_owned();
    let (status, headers, _) = request(
        &fx.app,
        &format!("/api/auth/oauth/google?ticket={ticket}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=mismatch");
    assert!(
        binding_of(&headers).is_none(),
        "no binding is issued on a refusal"
    );
    let (status, headers, _) = request(
        &fx.app,
        &format!("/api/auth/oauth/github?ticket={ticket}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
    // No ticket at all reads the same way.
    let (status, headers, _) = request(&fx.app, "/api/auth/oauth/github", None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
    // An unknown provider is refused by name.
    let (status, headers, _) = request(&fx.app, "/api/auth/oauth/gitlab?ticket=x", None).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location(&headers), "/login?oauth_error=state");
}

#[tokio::test]
async fn the_binding_cookie_is_http_only_lax_scoped_and_secure() {
    let fx = fixture("cookie");
    let begun = call(
        &fx.surface,
        "session.oauthBegin",
        json!({ "provider": "github", "token": null }),
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
    let (_, authorize, _) = start(&fx, json!({ "provider": "github", "token": null })).await;
    let target = callback(&fx, &authorize, "code=code-1", None).await;
    assert_eq!(target, "/login?oauth_error=binding");
    assert!(
        fx.http.calls.lock().expect("calls").is_empty(),
        "no token was exchanged"
    );

    // Mismatched cookie: same refusal, still no exchange.
    let (_, authorize, _) = start(&fx, json!({ "provider": "github", "token": null })).await;
    let target = callback(&fx, &authorize, "code=code-1", Some("not-the-binding")).await;
    assert_eq!(target, "/login?oauth_error=binding");
    assert!(fx.http.calls.lock().expect("calls").is_empty());

    // MUT:binding-per-attempt — another attempt's binding is a mismatch too.
    let (_, first, first_binding) =
        start(&fx, json!({ "provider": "github", "token": null })).await;
    let (_, second, second_binding) =
        start(&fx, json!({ "provider": "github", "token": null })).await;
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
    let target = round_trip(
        &fx,
        json!({ "provider": "github", "token": null }),
        "code=code-1",
    )
    .await;
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
        json!({ "provider": "github", "token": null, "returnTo": "/inbox?box=Sent" }),
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
    assert_eq!(result["admin"], true);
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
            json!({ "provider": "github", "token": null, "returnTo": asked }),
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
        json!({ "provider": "gitlab", "token": null }),
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
    let (_, authorize, binding) = start(&fx, json!({ "provider": "github", "token": null })).await;
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
    let (_, authorize, binding) = start(&fx, json!({ "provider": "github", "token": null })).await;
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
