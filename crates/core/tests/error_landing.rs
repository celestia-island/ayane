//! The family error landing on the full router.
//!
//! A failed browser NAVIGATION is answered with the service's own SPA shell
//! carrying the `hk-server-error` data island at the real status code, so
//! hikari's `createErrorReporting` paints the unified card instead of the
//! browser showing a tab of raw JSON. Everything that is not a navigation
//! keeps its bytes: a `fetch` caller still reads `{"error": …}`, a socket
//! upgrade is never rewritten, and a success is untouched.

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
use ayane::transport::RpcSurface;
use ayane_store::RedbStateStore;

const TOKEN: &str = "ayane-dev-admin-token";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ayane-landing-{tag}-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The full application (`full_router`: REST + ws/mcp), as `main` serves it.
fn fixture(tag: &str) -> Router {
    let root = temp_dir(tag);
    std::fs::create_dir_all(&root).expect("root");
    let store = RedbStateStore::open(root.join("store.redb")).expect("store");
    std::fs::write(root.join("docker-compose.yml"), "name: ayane\n").expect("compose stub");
    let config = Config {
        listen: "127.0.0.1:3023".parse().expect("listen"),
        log_filter: String::new(),
        state_dir: root.join("state"),
        admin_token: Some(TOKEN.to_owned()),
        compose_file: root.join("docker-compose.yml"),
        imap: "127.0.0.1:143".to_owned(),
        submission: "127.0.0.1:587".to_owned(),
        cert_file: None,
    };
    let app = AppState {
        store: Arc::new(store),
        driver: Arc::new(RecordingDriver::new(root.join("docker-compose.yml"))),
        config: Arc::new(config),
        auth: Arc::new(ayane::auth::AuthState::local()),
    };
    ayane::api::full_router(RpcSurface {
        app,
        sessions: Arc::new(ayane::session::SessionStore::new()),
    })
}

/// One request with the given method and headers; the reply whole.
async fn send(app: &Router, method: &str, uri: &str, headers: &[(&str, &str)]) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

/// The reply's body as text.
async fn body_text(response: Response) -> String {
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    String::from_utf8(body.to_vec()).expect("utf-8 body")
}

fn header_of(response: &Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// A browser navigating: `Sec-Fetch-Dest: document` and an `Accept` that
/// names HTML — what Chrome, Firefox and Safari send to a typed URL.
const NAVIGATION: &[(&str, &str)] = &[
    ("sec-fetch-dest", "document"),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
];

/// An unauthenticated read of the admin state: the REST face's routing
/// guard answers `401 {"error": "…"}`, a plain JSON error.
const UNAUTHORIZED_JSON: &str = "/api/v1/state";

#[tokio::test]
async fn the_landing_shell_is_the_document_the_spa_is_served() {
    // The landing must not carry a copy of the shell: the bytes the layer
    // wraps are `index_shell()`, and `GET /` answers from the same asset.
    let app = fixture("shell");
    let served = send(&app, "GET", "/", NAVIGATION).await;
    assert_eq!(served.status(), StatusCode::OK);
    let served_bytes = to_bytes(served.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let handed = ayane::webui::index_shell().expect("the front end is built");
    assert_eq!(
        served_bytes.to_vec(),
        handed.as_bytes(),
        "`GET /` and `index_shell()` must be the same bytes"
    );

    // And the shell the landing embeds starts from exactly those bytes:
    // the island is inserted into the document, nothing is rewritten.
    let landed = send(&app, "GET", UNAUTHORIZED_JSON, NAVIGATION).await;
    assert_eq!(landed.status(), StatusCode::UNAUTHORIZED);
    let landed_body = body_text(landed).await;
    let island_at = landed_body
        .find("</head>")
        .expect("the shell keeps its head");
    let without_island: String = {
        // Drop the injected island element, then the body must be the
        // served document again.
        let start = landed_body
            .find(r#"<script type="application/json" id="hk-server-error">"#)
            .expect("the island is in the landing");
        let end = landed_body[start..]
            .find("</script>")
            .map(|offset| start + offset + "</script>".len())
            .expect("the island is closed");
        format!("{}{}", &landed_body[..start], &landed_body[end..])
    };
    assert!(
        island_at < landed_body.len(),
        "the island sits inside the shell's head"
    );
    assert_eq!(
        without_island, handed,
        "the landing is the served shell plus the island, byte for byte"
    );
}

#[tokio::test]
async fn a_navigation_to_a_json_error_lands_on_the_shell() {
    let app = fixture("document");
    let response = send(&app, "GET", UNAUTHORIZED_JSON, NAVIGATION).await;

    // The real status code survives: a 401 stays a 401.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let content_type = header_of(&response, "content-type");
    assert!(
        content_type.starts_with("text/html"),
        "the landing is an HTML document, got {content_type:?}"
    );
    assert_eq!(header_of(&response, "cache-control"), "no-store");
    let body = body_text(response).await;
    // The island hikari reads on install, carrying this status.
    assert!(
        body.contains(r#"id="hk-server-error""#),
        "the island is in the document: {body:.400}"
    );
    assert!(
        body.contains(r#""status":401"#),
        "the island names the real status: {body:.600}"
    );
    // The shell is the SPA's own document, so the app boots from it.
    assert!(
        body.contains(r#"<div id="app">"#),
        "the mount point of the SPA shell is present: {body:.400}"
    );
    // The JSON the browser would otherwise have been shown is no longer
    // the DOCUMENT: the shell leads the body. The original response does
    // ride along inside the island's `raw` (the card's details pane shows
    // it), so the check is where the body starts, not what it contains.
    assert!(
        body.trim_start().starts_with("<!doctype html") || body.trim_start().starts_with("<html"),
        "a navigation gets the shell, not the bare JSON document: {body:.200}"
    );
}

#[tokio::test]
async fn a_fetch_of_the_same_route_keeps_its_json_byte_for_byte() {
    let app = fixture("fetch");
    let fetched = send(
        &app,
        "GET",
        UNAUTHORIZED_JSON,
        &[("sec-fetch-dest", "empty"), ("accept", "*/*")],
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::UNAUTHORIZED);
    let content_type = header_of(&fetched, "content-type");
    assert!(
        content_type.starts_with("application/json"),
        "a fetch keeps the JSON content type, got {content_type:?}"
    );
    let body = body_text(fetched).await;
    let error = serde_json::from_str::<serde_json::Value>(&body)
        .expect("the fetch caller's body is still one JSON document")
        .get("error")
        .and_then(serde_json::Value::as_str)
        .expect("the family error shape")
        .to_owned();
    assert!(
        !body.contains("hk-server-error"),
        "no landing island for a fetch caller"
    );

    // A client with no Sec-Fetch-* at all (curl, an MCP caller) that names
    // neither HTML nor a document: `*/*` is not a navigation, so the JSON
    // document comes back whole.
    let wildcard = send(&app, "GET", UNAUTHORIZED_JSON, &[("accept", "*/*")]).await;
    assert_eq!(wildcard.status(), StatusCode::UNAUTHORIZED);
    assert!(header_of(&wildcard, "content-type").starts_with("application/json"));
    assert!(
        !body_text(wildcard).await.contains("hk-server-error"),
        "`Accept: */*` is not a navigation"
    );

    // Same route, Accept naming JSON only (a client without Sec-Fetch-*):
    // the same JSON document, not the shell.
    let accepted = send(
        &app,
        "GET",
        UNAUTHORIZED_JSON,
        &[("accept", "application/json")],
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::UNAUTHORIZED);
    assert!(header_of(&accepted, "content-type").starts_with("application/json"));
    assert!(
        body_text(accepted)
            .await
            .contains(&format!(r#""error":"{error}""#)),
        "the JSON body is unchanged"
    );
}

#[tokio::test]
async fn a_successful_route_is_untouched() {
    let app = fixture("success");
    // `/api/health` is a 200 both a browser and a fetch reach.
    for headers in [NAVIGATION, &[("sec-fetch-dest", "empty")][..]] {
        let response = send(&app, "GET", "/api/health", headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(header_of(&response, "content-type").starts_with("application/json"));
        let body = body_text(response).await;
        assert!(
            !body.contains("hk-server-error"),
            "a success is never rewritten: {body:.300}"
        );
        assert!(serde_json::from_str::<serde_json::Value>(&body).is_ok());
    }

    // The SPA document itself is served as before, with no island: a
    // landing is for failures only.
    let shell = send(&app, "GET", "/", NAVIGATION).await;
    assert_eq!(shell.status(), StatusCode::OK);
    assert!(header_of(&shell, "content-type").starts_with("text/html"));
    let body = body_text(shell).await;
    assert!(
        !body.contains("hk-server-error"),
        "a successful navigation gets the plain shell"
    );
    assert!(body.contains(r#"<div id="app">"#));
}

#[tokio::test]
async fn the_socket_and_machine_surfaces_keep_their_bodies() {
    let app = fixture("machine");
    // The OAuth failure path is a 302 to the login view — 3xx is not an
    // error, so a navigation keeps its redirect and the SPA shows its own
    // message.
    let oauth = send(&app, "GET", "/api/auth/oauth/nope?ticket=x", NAVIGATION).await;
    assert_eq!(oauth.status(), StatusCode::FOUND);
    let location = header_of(&oauth, "location");
    assert!(
        location.starts_with("/login?oauth_error="),
        "the OAuth failure keeps its 302, got {location:?}"
    );

    // The MCP surface's 401 is a JSON-RPC error: unchanged for its caller.
    let mcp = send(
        &app,
        "POST",
        "/api/mcp",
        &[
            ("sec-fetch-dest", "empty"),
            ("accept", "application/json"),
            ("content-type", "application/json"),
        ],
    )
    .await;
    assert_eq!(mcp.status(), StatusCode::UNAUTHORIZED);
    assert!(header_of(&mcp, "content-type").starts_with("application/json"));
    assert!(
        !body_text(mcp).await.contains("hk-server-error"),
        "the machine surface keeps its JSON-RPC error"
    );

    // An Upgrade request WITHOUT `Sec-Fetch-Dest` and WITHOUT an `Accept`
    // naming HTML: the Accept fallback is false too, so the only thing that
    // can keep this out of the landing is plana's Upgrade short-circuit —
    // the point of this pin. (A handshake needs a real server: the upgrade
    // extractor takes an extension only the HTTP connection inserts, so
    // `oneshot` answers 426 to every handshake.)
    let addr = serve(app).await;

    let bare = upgrade_head(addr, "mail.example.test", Some("https://evil.test"), false).await;
    assert_eq!(
        status_of(&bare),
        403,
        "a foreign origin is refused by the handler, got {bare:?}"
    );
    assert!(
        bare.to_ascii_lowercase()
            .contains("content-type: text/plain"),
        "the bare upgrade keeps its plain-text refusal: {bare:?}"
    );
    assert!(
        !bare.contains("hk-server-error") && !bare.to_ascii_lowercase().contains("text/html"),
        "an upgrade with neither Sec-Fetch-Dest nor an HTML Accept is never \
         rewritten into the landing: {bare:?}"
    );

    // The same shape on a GOOD origin: the handshake succeeds (101), which
    // also proves the layer let the upgrade through untouched.
    let accepted = upgrade_head(
        addr,
        "mail.example.test",
        Some("https://mail.example.test"),
        false,
    )
    .await;
    assert_eq!(
        status_of(&accepted),
        101,
        "a same-origin upgrade still upgrades: {accepted:?}"
    );
    assert!(
        accepted
            .to_ascii_lowercase()
            .contains("sec-websocket-accept:"),
        "the upgrade is the socket's, not a document: {accepted:?}"
    );
}

/// The full application on a loopback socket of its own.
async fn serve(app: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

/// One WebSocket handshake as a browser opens it — a raw HTTP/1.1 upgrade
/// with every header the upgrade needs, the browser's `Sec-Fetch-Dest`
/// included. Answers the head of the reply (status line and headers).
async fn upgrade_head(
    addr: std::net::SocketAddr,
    host: &str,
    origin: Option<&str>,
    browser_fetch_headers: bool,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut request = format!(
        "GET /api/ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    );
    if browser_fetch_headers {
        request
            .push_str("Sec-Fetch-Dest: websocket\r\nSec-Fetch-Mode: websocket\r\nAccept: */*\r\n");
    }
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
