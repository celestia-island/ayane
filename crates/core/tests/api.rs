//! API-level tests: routing, auth, state round-trip and the apply loop,
//! all against a temporary store and a recording driver — no engine needed.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use tower::ServiceExt;

use ayane::config::Config;
use ayane::driver::RecordingDriver;
use ayane::state::AppState;
use ayane_store::RedbStateStore;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ayane-api-{tag}-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

struct Fixture {
    app: Router,
    state_dir: PathBuf,
}

fn fixture(tag: &str, token: Option<&str>) -> Fixture {
    let root = temp_dir(tag);
    let store = RedbStateStore::open(root.join("store.redb")).expect("store");
    let driver = RecordingDriver::new(root.join("docker-compose.yml"));
    std::fs::write(root.join("docker-compose.yml"), "name: ayane\n").expect("compose stub");
    let config = Config {
        listen: "127.0.0.1:3023".parse().expect("listen"),
        log_filter: String::new(),
        state_dir: root.join("state"),
        admin_token: token.map(str::to_owned),
        compose_file: root.join("docker-compose.yml"),
        imap: "127.0.0.1:143".to_owned(),
        submission: "127.0.0.1:587".to_owned(),
        cert_file: None,
        // The mail section is off in every control-plane test: the default
        // `MailConfig` is what an installation that has not enabled it gets,
        // and a test that does not opt in must not bind a port.
        mail: ayane::config::MailConfig::default(),
    };
    let app = ayane::app(AppState {
        store: Arc::new(store),
        driver: Arc::new(driver),
        config: Arc::new(config),
        auth: Arc::new(ayane::auth::AuthState::local()),
    });
    Fixture {
        app,
        state_dir: root.join("state"),
    }
}

async fn get(app: &Router, uri: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri(uri);
    if let Some(token) = token {
        builder = builder.header("x-admin-token", token);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).expect("json body")
    };
    (status, value)
}

/// One GET and the whole reply, headers included (`get` keeps only what
/// a JSON body needs).
async fn get_raw(app: &Router, uri: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response")
}

/// The reply's `content-type`, for when the body's kind is the point.
fn content_type(response: &Response) -> &str {
    response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

async fn put_state(app: &Router, token: &str) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "domains": [
            {"name": "example.test", "catch_all": "inbox@example.test", "enabled": true}
        ],
        "accounts": [
            {"address": "alice@example.test", "display_name": "Alice",
             "quota_bytes": 0, "password": "ayane-dev-pass-1"},
            {"address": "boss@example.test", "display_name": "Boss",
             "quota_bytes": 0, "password": "ayane-dev-pass-2"},
            {"address": "inbox@example.test", "display_name": "Inbox",
             "quota_bytes": 0, "password": "ayane-dev-pass-3"}
        ],
        "aliases": [
            {"source": "sales@example.test", "targets": ["boss@example.test"]}
        ],
        "shared": [],
        "policy": {"default_action": "reject", "allowlist": [], "denylist": []}
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/state")
                .header("x-admin-token", token)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, serde_json::from_slice(&body).expect("json"))
}

#[tokio::test]
async fn health_is_open_and_reports_the_engine_stack() {
    let fixture = fixture("health", None);
    let (status, value) = get(&fixture.app, "/api/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["service"], "ayane");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["engine"]["mta"], "postfix");
    assert_eq!(value["engine"]["filter"], "rspamd");
}

// MUT:api-fallback-never-spa
#[tokio::test]
async fn an_unknown_api_route_is_a_json_404_never_the_spa() {
    let fixture = fixture("fallback", None);

    // A path under `/api/` that no route matched is a missing API route:
    // the uniform error body with a 404 — never `index.html` with a 200.
    for uri in ["/api/v1/does-not-exist", "/api/auth/nope"] {
        let response = get_raw(&fixture.app, uri).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert!(
            content_type(&response).starts_with("application/json"),
            "{uri}: {}",
            content_type(&response)
        );
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert!(
            value["error"]
                .as_str()
                .is_some_and(|error| error.contains(uri)),
            "{uri}: {value}"
        );
    }

    // A client route is still the SPA's document.
    let response = get_raw(&fixture.app, "/inbox/x").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        content_type(&response).starts_with("text/html"),
        "{}",
        content_type(&response)
    );
}

#[tokio::test]
async fn management_requires_the_admin_token() {
    let fixture = fixture("auth", Some("sekret"));
    let (status, _) = get(&fixture.app, "/api/v1/state", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get(&fixture.app, "/api/v1/state", Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Bearer form on the Authorization header must work identically.
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/state")
                .header("authorization", "Bearer sekret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/state")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (status, value) = get(&fixture.app, "/api/v1/state", Some("sekret")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["domains"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn management_is_disabled_without_a_configured_token() {
    let fixture = fixture("no-token", None);
    let (status, value) = get(&fixture.app, "/api/v1/state", Some("anything")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(value["error"].as_str().unwrap().contains("ADMIN_TOKEN"));
}

#[tokio::test]
async fn put_state_stores_and_redacts() {
    let fixture = fixture("put", Some("sekret"));
    let (status, ack) = put_state(&fixture.app, "sekret").await;
    assert_eq!(status, StatusCode::OK, "ack {ack}");
    assert_eq!(ack["domains"], 1);
    assert_eq!(ack["accounts"], 3);
    assert_eq!(ack["aliases"], 1);

    let (status, state) = get(&fixture.app, "/api/v1/state", Some("sekret")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["accounts"].as_array().map(Vec::len), Some(3));
    assert_eq!(state["domains"][0]["catch_all"], "inbox@example.test");
    let serialized = state.to_string();
    assert!(
        !serialized.contains("ayane-dev-pass"),
        "GET state must never expose passwords: {serialized}"
    );
}

#[tokio::test]
async fn put_state_rejects_short_passwords_and_bad_state() {
    let fixture = fixture("put-invalid", Some("sekret"));
    let body = serde_json::json!({
        "domains": [{"name": "example.test", "catch_all": null, "enabled": true}],
        "accounts": [
            {"address": "alice@example.test", "display_name": "A",
             "quota_bytes": 0, "password": "short"}
        ],
        "aliases": [], "shared": [],
        "policy": {"default_action": "reject", "allowlist": [], "denylist": []}
    });
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/state")
                .header("x-admin-token", "sekret")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Foreign catch-all must also be rejected with 422.
    let body = serde_json::json!({
        "domains": [{"name": "example.test", "catch_all": "inbox@other.test", "enabled": true}],
        "accounts": [
            {"address": "alice@example.test", "display_name": "A",
             "quota_bytes": 0, "password": "ayane-dev-pass-1"}
        ],
        "aliases": [], "shared": [],
        "policy": {"default_action": "reject", "allowlist": [], "denylist": []}
    });
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/state")
                .header("x-admin-token", "sekret")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn apply_writes_config_then_rewrites_nothing() {
    let fixture = fixture("apply", Some("sekret"));
    put_state(&fixture.app, "sekret").await;

    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/apply")
                .header("x-admin-token", "sekret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let report: serde_json::Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body"),
    )
    .expect("report");
    let changed: Vec<_> = report["files"]
        .as_array()
        .expect("files")
        .iter()
        .filter(|f| f["changed"] == serde_json::Value::Bool(true))
        .collect();
    // Eight rendered maps, plus the routing snapshot the delivery consumer and
    // the split-process listener read (`desired-state.json`).
    assert_eq!(changed.len(), 9, "first apply writes every file: {report}");
    // The sender-login map rides every apply (2026-11-25): it is the table
    // reject_sender_login_mismatch consults on the submission ports.
    let login = fixture.state_dir.join("config/postfix/sender_login");
    let login_map = std::fs::read_to_string(&login).expect("sender_login");
    assert!(
        login_map.contains("alice@example.test alice@example.test"),
        "{login_map}"
    );

    let passwd = fixture.state_dir.join("config/dovecot/passwd");
    let contents = std::fs::read_to_string(&passwd).expect("passwd");
    assert!(contents.contains("alice@example.test:{SHA512-CRYPT}$6$rounds=10000$"));
    let mode = std::fs::metadata(&passwd)
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "passwd must be 0600, got {mode:o}");
    let maps = std::fs::read_to_string(fixture.state_dir.join("config/postfix/virtual_mailboxes"))
        .expect("maps");
    assert!(maps.contains("boss@example.test OK\n"));
    // The Gmail-style variant map is always written, and is empty (a no-op
    // table) while every inbound switch is off.
    let variants = fixture.state_dir.join("config/postfix/variant_aliases");
    assert_eq!(std::fs::read_to_string(&variants).expect("variant map"), "");

    let response = fixture
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/apply")
                .header("x-admin-token", "sekret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let report: serde_json::Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body"),
    )
    .expect("report 2");
    let changed: Vec<_> = report["files"]
        .as_array()
        .expect("files")
        .iter()
        .filter(|f| f["changed"] == serde_json::Value::Bool(true))
        .collect();
    assert!(
        changed.is_empty(),
        "second apply must rewrite nothing: {report}"
    );
    // One service now: the SMTP listeners, hot-swapped. Postfix, Dovecot and
    // rspamd are not in the process (or in the path) any more, so a report that
    // still named three would be naming daemons nothing reloads.
    assert_eq!(
        report["reloaded"].as_array().map(Vec::len),
        Some(1),
        "the one service this engine reloads: {report}"
    );
    assert_eq!(report["reloaded"][0]["service"], "smtp", "{report}");
}
