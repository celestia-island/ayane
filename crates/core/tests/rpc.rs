//! JSON-RPC surface contract tests: envelope shape, error paths, session
//! gates. These drive `handle_one` directly — the socket plumbing is thin
//! frame in/out and needs no test doubles — except for the handshake gate,
//! which is the HTTP layer's own: that one opens a real socket.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use serde_json::{json, Value};

use ayane::state::AppState;
use ayane::transport::RpcSurface;
use ayane_store::{password, RedbStateStore, StateStore, StoredState};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ayane-rpc-{tag}-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

const PASSWORD: &str = "correct-horse-battery";
const ADMIN: &str = "admin-secret-token";

async fn surface(tag: &str) -> (RpcSurface, PathBuf) {
    let root = temp_dir(tag);
    let store = RedbStateStore::open(root.join("store.redb")).expect("store");
    let mut hashes = std::collections::HashMap::new();
    hashes.insert(
        "test@example.test".to_owned(),
        password::hash_password(PASSWORD).expect("hash"),
    );
    let stored = StoredState {
        desired: ayane_proto::DesiredState {
            domains: vec![ayane_proto::MailDomain {
                name: "example.test".to_owned(),
                catch_all: None,
                enabled: true,
            }],
            accounts: vec![ayane_proto::Account {
                id: uuid::Uuid::new_v4(),
                address: ayane_proto::Address::parse("test@example.test").expect("addr"),
                display_name: "Test".to_owned(),
                quota_bytes: 0,
                admin: false,
            }],
            ..Default::default()
        },
        password_hashes: hashes,
        external_identities: Vec::new(),
    };
    store.save(&stored).expect("seed");
    let config = ayane::config::Config {
        listen: "127.0.0.1:3023".parse().expect("listen"),
        log_filter: String::new(),
        state_dir: root.join("state"),
        admin_token: Some(ADMIN.to_owned()),
        compose_file: root.join("docker-compose.yml"),
        // Nothing listens here in tests: the mail arm must fail with
        // Mail.ImapFailed rather than anything catastrophic.
        imap: "127.0.0.1:1".to_owned(),
        submission: "127.0.0.1:1".to_owned(),
        cert_file: None,
    };
    let app = AppState {
        store: Arc::new(store),
        driver: Arc::new(ayane::driver::RecordingDriver::new(
            root.join("docker-compose.yml"),
        )),
        config: Arc::new(config),
        auth: Arc::new(ayane::auth::AuthState::local()),
    };
    let surface = RpcSurface {
        app,
        sessions: Arc::new(ayane::session::SessionStore::new()),
    };
    (surface, root)
}

async fn call(surface: &RpcSurface, request: Value) -> Value {
    let mut ctx = ayane::rpc::WsContext::new();
    let text = ayane::transport::handle_one_for_tests(surface, &mut ctx, &request.to_string())
        .await
        .expect("reply for request");
    serde_json::from_str(&text).expect("json reply")
}

#[tokio::test]
async fn ping_answers_result() {
    let (surface, _root) = surface("ping").await;
    let reply = call(&surface, rpc_request("session.ping", json!({}), json!(1))).await;
    assert_eq!(reply["result"]["ok"], json!(true));
}

#[tokio::test]
async fn unknown_method_is_32601() {
    let (surface, _) = surface("unknown").await;
    let reply = call(&surface, rpc_request("nope.nope", json!({}), json!(2))).await;
    assert_eq!(reply["error"]["code"], json!(-32601));
}

#[tokio::test]
async fn malformed_json_is_32700() {
    let (surface, _) = surface("malformed").await;
    let mut ctx = ayane::rpc::WsContext::new();
    let text = ayane::transport::handle_one_for_tests(&surface, &mut ctx, "{ not json")
        .await
        .expect("reply");
    let reply: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(reply["error"]["code"], json!(-32700));
}

#[tokio::test]
async fn notifications_are_never_answered() {
    let (surface, _) = surface("notify").await;
    let mut ctx = ayane::rpc::WsContext::new();
    // A notification carries NO id member at all (`id: null` is a valid,
    // discouraged id and must be answered).
    let notification = json!({ "jsonrpc": "2.0", "method": "session.ping", "params": {} });
    assert!(
        ayane::transport::handle_one_for_tests(&surface, &mut ctx, &notification.to_string())
            .await
            .is_none(),
        "notifications must produce no reply"
    );
}

#[tokio::test]
async fn wrong_password_is_a_path_error() {
    let (surface, _) = surface("badpw").await;
    let reply = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": "wrong" }),
            json!(3),
        ),
    )
    .await;
    assert_eq!(reply["error"]["code"], json!(-32000));
    assert_eq!(
        reply["error"]["message"].as_str().expect("message"),
        "Session.InvalidCredentials: address or password is wrong"
    );
}

#[tokio::test]
async fn login_then_mail_fails_gracefully_without_imap() {
    let (surface, _) = surface("mailgate").await;
    let login = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": PASSWORD }),
            json!(1),
        ),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token").to_owned();
    assert_eq!(login["result"]["address"], "test@example.test");

    let reply = call(
        &surface,
        rpc_request("mail.list", json!({ "token": token }), json!(2)),
    )
    .await;
    assert_eq!(reply["error"]["code"], json!(-32000));
    assert!(
        reply["error"]["message"]
            .as_str()
            .expect("message")
            .starts_with("Mail.ImapFailed:"),
        "got {}",
        reply["error"]["message"]
    );
}

#[tokio::test]
async fn admin_methods_require_an_admin_session() {
    let (surface, _) = surface("admingate").await;
    // Anonymous.
    let reply = call(
        &surface,
        rpc_request("admin.state.get", json!({}), json!(1)),
    )
    .await;
    assert_eq!(
        reply["error"]["message"].as_str().expect("m"),
        "Session.Required: login first"
    );

    // A mailbox session is NOT an admin session.
    let login = call(
        &surface,
        rpc_request(
            "session.login",
            json!({ "address": "test@example.test", "password": PASSWORD }),
            json!(2),
        ),
    )
    .await;
    let token = login["result"]["token"].as_str().expect("token");
    let reply = call(
        &surface,
        rpc_request("admin.state.get", json!({ "token": token }), json!(3)),
    )
    .await;
    assert_eq!(
        reply["error"]["message"].as_str().expect("m"),
        "Admin.Forbidden: admin account required"
    );

    // Admin login opens the gate and the state flows back.
    let admin = call(
        &surface,
        rpc_request("session.adminLogin", json!({ "token": ADMIN }), json!(4)),
    )
    .await;
    assert_eq!(admin["result"]["ok"], json!(true));
    let admin_token = admin["result"]["token"].as_str().expect("admin token");
    let state = call(
        &surface,
        rpc_request("admin.state.get", json!({ "token": admin_token }), json!(5)),
    )
    .await;
    assert_eq!(state["result"]["domains"][0]["name"], "example.test");
}

fn rpc_request(method: &str, params: Value, id: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// The full application on a loopback socket of its own: the address to
/// reach it at. (A WebSocket handshake only survives a real server: the
/// upgrade extractor takes an extension the HTTP connection itself
/// inserts, so `tower::oneshot` answers 426 to every handshake.)
async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

/// One WebSocket handshake at `addr`, as a browser would open it: a raw
/// HTTP/1.1 upgrade request with every header the upgrade needs, the
/// `Host` given and the `Origin` given (`None` = the header is not sent
/// at all). Answers the head of the reply — status line and headers.
async fn upgrade_head(addr: SocketAddr, host: &str, origin: Option<&str>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut request = format!(
        "GET /api/ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    );
    if let Some(origin) = origin {
        request.push_str(&format!("Origin: {origin}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.expect("send");
    // The head ends at the first empty line; the body (for an accepted
    // upgrade, the socket itself) is never read.
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.expect("read");
        assert!(
            read > 0,
            "closed before the head ended: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.extend_from_slice(&chunk[..read]);
        if let Ok(text) = std::str::from_utf8(&head) {
            if let Some(end) = text.find("\r\n\r\n") {
                return text[..end].to_owned();
            }
        }
    }
}

/// The status code of a reply's head.
fn status_of(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status")
}

/// Whether the head carries the handshake's own acceptance header.
fn accepted(head: &str) -> bool {
    head.to_ascii_lowercase().contains("sec-websocket-accept:")
}

#[tokio::test]
async fn the_websocket_refuses_a_foreign_origin() {
    let (surface, _root) = surface("ws-origin").await;
    let addr = serve(ayane::api::full_router(surface)).await;
    let own = "mail.example.test";

    // MUT:ws-same-origin — the socket is upgraded only for this origin:
    // the `Origin` the browser names is the `Host` its request came to
    // (name and port; the case of the name is nobody's, and a port the
    // scheme makes the default goes unnamed on either side). The SPA's
    // page.
    for (host, origin) in [
        (own, "https://mail.example.test"),
        (own, "https://Mail.Example.Test"),
        ("127.0.0.1:3023", "http://127.0.0.1:3023"),
        ("mail.example.test:443", "https://mail.example.test"),
        ("mail.example.test:8443", "https://mail.example.test:8443"),
        ("[::1]:3023", "http://[::1]:3023"),
    ] {
        let head = upgrade_head(addr, host, Some(origin)).await;
        assert_eq!(status_of(&head), 101, "{origin} on {host}: {head}");
        assert!(accepted(&head), "{origin} on {host}: {head}");
    }
    // No `Origin` at all is not a browser: the MCP/WS tooling.
    let head = upgrade_head(addr, own, None).await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert!(accepted(&head), "{head}");

    // Any other origin is refused before the handshake: another host,
    // another port, the `null` origin, a host that merely starts with
    // ours, ours on another port, a scheme no page has — and an origin
    // with no `Host` to vouch for it.
    for (host, origin) in [
        (own, "https://evil.example"),
        (own, "https://mail.example.test:8443"),
        (own, "null"),
        (own, "https://mail.example.test.evil.example"),
        (own, "ws://mail.example.test"),
        ("127.0.0.1:3023", "https://mail.example.test"),
        ("", "https://mail.example.test"),
    ] {
        let head = upgrade_head(addr, host, Some(origin)).await;
        assert_eq!(status_of(&head), 403, "{origin} on {host:?}: {head}");
        assert!(!accepted(&head), "{origin} on {host:?}: {head}");
    }
}
