//! Transports for the JSON-RPC surface.
//!
//! `/api/ws` — the webmail's streaming socket (one JSON-RPC request per
//! text frame, one response frame back, notifications produce nothing).
//! `/api/mcp` — HTTP POST for agents: the same dispatch, one shot, the
//! MCP tool vocabulary (`tools/list`, `tools/call`) mapped onto it.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::rpc::{self, ProtocolError, RpcOutcome, WsContext};
use crate::session::SessionStore;
use crate::state::AppState;

/// Shared handle: the session store lives beside the app state.
#[derive(Clone)]
pub struct RpcSurface {
    /// The application state.
    pub app: AppState,
    /// Login sessions for both transports.
    pub sessions: Arc<SessionStore>,
}

/// The WebSocket upgrade handler.
///
/// # Errors
///
/// Returns an axum response (never a Rust error): the upgrade either
/// proceeds or the handshake failed at the HTTP layer before this returns.
pub async fn ws_handler(State(surface): State<RpcSurface>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| ws_loop(surface, socket))
}

async fn ws_loop(surface: RpcSurface, mut socket: WebSocket) {
    let mut ctx = WsContext::new();
    while let Some(Ok(frame)) = socket.recv().await {
        let Message::Text(text) = frame else {
            continue; // binary/ping frames are not part of the contract
        };
        let reply = handle_one(&surface, &mut ctx, &text).await;
        if let Some(payload) = reply {
            if socket.send(Message::Text(payload.into())).await.is_err() {
                break;
            }
        }
    }
}

/// Handle one text frame; `None` for notifications (no `id`).
async fn handle_one(surface: &RpcSurface, ctx: &mut WsContext, text: &str) -> Option<String> {
    handle_one_inner(surface, ctx, text).await
}

/// Test seam: the same handler without the socket.
#[doc(hidden)]
pub async fn handle_one_for_tests(
    surface: &RpcSurface,
    ctx: &mut WsContext,
    text: &str,
) -> Option<String> {
    handle_one(surface, ctx, text).await
}

async fn handle_one_inner(surface: &RpcSurface, ctx: &mut WsContext, text: &str) -> Option<String> {
    let request: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(e) => {
            return Some(
                json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") }
                })
                .to_string(),
            )
        }
    };
    let id = request.get("id").cloned();
    let Some(id) = id else {
        return None; // notification: accepted, never answered
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Some(protocol_reply(Some(id), -32600, "missing method"));
    };
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

    let outcome = rpc::dispatch(&surface.app, &surface.sessions, ctx, method, params).await;
    let body = match outcome {
        RpcOutcome::Result(result) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        RpcOutcome::App(err) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32000, "message": err.to_string() }
        }),
        RpcOutcome::Protocol(ProtocolError { code, message }) => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": code, "message": message }
            })
        }
    };
    Some(body.to_string())
}

fn protocol_reply(id: Option<Value>, code: i32, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
    .to_string()
}

/// `POST /api/mcp` — MCP's JSON-RPC over plain HTTP for agents.
///
/// Auth: `Authorization: Bearer <admin-token>` or `X-Admin-Token`; agent
/// tooling never holds mailbox passwords.
///
/// # Errors
///
/// Returns a JSON-RPC error response (HTTP 200) for every RPC-level
/// failure; transport-level problems answer 401.
pub async fn mcp_handler(
    State(surface): State<RpcSurface>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let presented = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::to_owned)
        });
    // Two accepted credentials: the env admin token (the operator's own
    // access) and the state-configured MCP token (the agent surface,
    // rotatable from the admin page). The MCP token also gates the tool
    // list: a caller holding it may only reach the enabled tools.
    let mcp_config = surface
        .app
        .store
        .load()
        .ok()
        .map(|stored| stored.desired.mcp)
        .unwrap_or_default();
    let constant_time_eq = |a: &str, b: &str| {
        a.len() == b.len()
            && a.bytes()
                .zip(b.bytes())
                .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                == 0
    };
    let presented = presented.as_deref();
    let admin_authed = matches!(
        (surface.app.config.admin_token.as_deref(), presented),
        (Some(a), Some(b)) if constant_time_eq(a, b)
    );
    let mcp_authed = !mcp_config.token.is_empty()
        && presented.is_some_and(|b| constant_time_eq(&mcp_config.token, b));
    if !admin_authed && !mcp_authed {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({
                "jsonrpc": "2.0", "id": null,
                "error": { "code": -32000, "message": "Admin.Forbidden: admin token required" }
            })),
        )
            .into_response();
    }
    // An MCP-token caller is confined to the configured tool surface; the
    // admin token keeps the whole dispatch table.
    let tool_gate: Option<Vec<String>> = if mcp_authed && !admin_authed {
        Some(mcp_config.tools.clone())
    } else {
        None
    };

    // The agent surface runs with an admin context pinned to the socket.
    // An MCP-token caller (not the admin token) gets a session minted from
    // the MCP token itself — the dispatch table's admin gates see a valid
    // admin session, and the tool gate below confines what it can reach.
    let mut ctx = WsContext::new();
    let credential = if admin_authed {
        surface.app.config.admin_token.clone()
    } else {
        Some(mcp_config.token.clone())
    };
    if let Ok((token, _)) = surface
        .sessions
        .admin_login(credential.as_deref(), presented.unwrap_or_default())
    {
        ctx.token = Some(token);
    }

    let request: Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(e) => {
            return Json(json!({
                "jsonrpc": "2.0", "id": null,
                "error": { "code": -32700, "message": format!("parse error: {e}") }
            }))
            .into_response()
        }
    };
    let id = request.get("id").cloned();
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        let reply: Value = serde_json::from_str(&protocol_reply(id, -32600, "missing method"))
            .expect("valid json");
        return Json(reply).into_response();
    };
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

    // MCP vocabulary: initialize + tools/list + tools/call map onto the
    // dispatch table's native methods.
    let (method, params) = match method {
        "initialize" => ("session.ping", json!({})),
        "tools/list" => {
            // The catalog answers the configured surface: an MCP-token
            // caller sees only the enabled tools (the admin token sees
            // everything).
            let tools = match &tool_gate {
                Some(enabled) => mcp_tools()
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|tool| {
                        tool.get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| enabled.contains(&name.to_owned()))
                    })
                    .collect::<Vec<_>>(),
                None => mcp_tools().as_array().cloned().unwrap_or_default(),
            };
            return Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": tools }
            }))
            .into_response();
        }
        "tools/call" => {
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let tool = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let native = mcp_native_name(tool);
            if let Some(enabled) = &tool_gate {
                let exposed = enabled
                    .iter()
                    .any(|candidate| mcp_native_name(candidate) == native);
                if !exposed {
                    return Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": format!("tool not enabled: {tool}") }
                    }))
                    .into_response();
                }
            }
            (native, args)
        }
        other => (other, params),
    };

    let outcome = rpc::dispatch(&surface.app, &surface.sessions, &mut ctx, method, params).await;
    let body = match outcome {
        RpcOutcome::Result(result) => json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "content": [ { "type": "text", "text": result.to_string() } ], "isError": false }
        }),
        RpcOutcome::App(err) => json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "content": [ { "type": "text", "text": err.to_string() } ], "isError": true }
        }),
        RpcOutcome::Protocol(e) => json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": e.code, "message": e.message }
        }),
    };
    Json(body).into_response()
}

/// MCP tool name → dispatch method (v1: everything admin-scoped).
fn mcp_native_name(tool: &str) -> &str {
    match tool {
        "dns.check" => "dns.check",
        "state.get" => "admin.state.get",
        "state.put" => "admin.state.put",
        "apply" => "admin.apply",
        other => other,
    }
}

/// The v1 MCP tool catalog.
#[must_use]
pub fn mcp_tools() -> Value {
    json!([
        { "name": "state.get", "description": "Read the current desired mail state (domains, accounts, aliases, policy)." },
        { "name": "state.put", "description": "Replace the desired state (same schema as state.get plus account passwords)." },
        { "name": "apply", "description": "Render the desired state into engine configuration and reload the daemons." },
    ])
}
