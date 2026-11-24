//! The embedded webmail single-page app.
//!
//! `packages/webui` builds to `dist/`; in release builds the tree is
//! compiled into the binary (rust-embed), in debug it is served straight
//! from disk so front-end iteration needs no rebuild. Unknown paths fall
//! back to `index.html` — SPA routing owns everything under `/` that is
//! not an API route, except a path under `/api/` that no API route
//! matched: that one is the API's own 404, never the SPA.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../../packages/webui/dist"]
struct Assets;

/// Serve one static asset, or `index.html` for SPA routes.
///
/// A path under `/api/` that reached this fallback matched no API route
/// and is no client route either: it is answered with the API's uniform
/// error body, never with the SPA (a caller that asked for JSON must not
/// be handed `index.html` with a 200).
///
/// # Errors
///
/// Returns a 404 response (never a Rust error) when the path resolves to
/// nothing and `index.html` itself is missing (front-end not built).
pub async fn serve(uri: Uri) -> Response {
    // MUT:api-fallback-never-spa — checked before any asset is looked
    // up, so nothing under `/api/` is ever served from here.
    if uri.path().starts_with("/api/") {
        return crate::api::ApiError::not_found(uri.path()).into_response();
    }
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(asset) = Assets::get(path) {
        let mime = mime_for(path);
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, cache_for(path)),
            ],
            asset.data,
        )
            .into_response();
    }

    // SPA fallback: anything that is not a file is a client route.
    match Assets::get("index.html") {
        Some(index) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            index.data,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "webui not built").into_response(),
    }
}

fn mime_for(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn cache_for(path: &str) -> &'static str {
    // Hashed assets are immutable; the documents are not.
    if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}
