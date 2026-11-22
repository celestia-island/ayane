//! The JSON-RPC method table — the family contract.
//!
//! One dispatch walks both transports: the WebSocket at `/api/ws`
//! (streaming, what the webmail speaks) and HTTP POST `/api/mcp` (agents).
//! The envelope is JSON-RPC 2.0; error identity is the family's
//! method-style path (`Session.InvalidCredentials: prose`) riding the
//! message with the `-32000` placeholder code — the convention
//! shittim-chest ruled in 2026-10-11 (the path is the machine channel).
//!
//! The IMAP leg needs the mailbox password and the store only keeps
//! hashes, so a session carries the plaintext **in memory only**, for its
//! TTL, and never persists or logs it.

use serde_json::{json, Value};

use ayane_mail::client::{Imap, MarkSeen, Submission};

use crate::api::PutState;
use crate::apply;
use crate::session::{LoginError, Session, SessionStore};
use crate::state::AppState;

/// Application error: path + prose (renders as `-32000` with
/// `"<Path>: <prose>"`).
#[derive(Debug, Clone)]
pub struct AppError {
    /// Domain-first PascalCase path, e.g. `Session.InvalidCredentials`.
    pub path: &'static str,
    /// Human-readable prose.
    pub prose: String,
}

impl AppError {
    /// Build an application error.
    #[must_use]
    pub fn new(path: &'static str, prose: impl Into<String>) -> Self {
        Self {
            path,
            prose: prose.into(),
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.prose)
    }
}

/// A protocol-level failure (malformed envelope, unknown method).
#[derive(Debug, Clone)]
pub struct ProtocolError {
    /// JSON-RPC code (-32600/-32601/-32602).
    pub code: i32,
    /// Short message.
    pub message: String,
}

/// Dispatch outcome for one request.
pub enum RpcOutcome {
    /// A result value for `id`.
    Result(Value),
    /// An application error for `id`.
    App(AppError),
    /// A protocol error for `id`.
    Protocol(ProtocolError),
}

/// Per-connection auth state: the token the connection last authenticated
/// with (methods may still override it via `params.token`).
#[derive(Debug, Default)]
pub struct WsContext {
    /// The cached bearer token for this connection.
    pub token: Option<String>,
}

impl WsContext {
    /// A fresh, unauthenticated context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Dispatch one JSON-RPC method call.
pub async fn dispatch(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    method: &str,
    params: Value,
) -> RpcOutcome {
    match method {
        "session.ping" => RpcOutcome::Result(json!({ "ok": true })),
        "session.login" => wrap(login(app, sessions, ctx, &params)),
        "session.adminLogin" => wrap(admin_login(app, sessions, ctx, &params)),
        "session.whoami" => match session_of(sessions, ctx, &params) {
            Ok(session) => RpcOutcome::Result(json!({
                "address": session.address.as_str(),
                "display_name": session.display_name,
                "admin": session.admin,
            })),
            Err(e) => RpcOutcome::App(e),
        },
        "session.logout" => {
            if let Some(token) = token_of(&params).or_else(|| ctx.token.clone()) {
                sessions.logout(&token);
            }
            ctx.token = None;
            RpcOutcome::Result(json!({ "ok": true }))
        }
        "mail.list" => mail_route(app, sessions, ctx, &params, mail_list).await,
        "mail.read" => mail_route(app, sessions, ctx, &params, mail_read).await,
        "mail.send" => mail_route(app, sessions, ctx, &params, mail_send).await,
        "mail.markSeen" => mail_route(app, sessions, ctx, &params, mail_mark_seen).await,
        "admin.state.get" => match require_admin(sessions, ctx, &params) {
            Ok(()) => RpcOutcome::Result(load_state(app)),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.state.put" => match require_admin(sessions, ctx, &params) {
            Ok(()) => wrap_result(put_state(app, &params).await),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.apply" => match require_admin(sessions, ctx, &params) {
            Ok(()) => wrap_result(do_apply(app).await),
            Err(e) => RpcOutcome::App(e),
        },
        other => RpcOutcome::Protocol(ProtocolError {
            code: -32601,
            message: format!("method not found: {other}"),
        }),
    }
}

fn wrap(result: Result<Value, AppError>) -> RpcOutcome {
    wrap_result(result)
}

fn wrap_result(result: Result<Value, AppError>) -> RpcOutcome {
    match result {
        Ok(value) => RpcOutcome::Result(value),
        Err(e) => RpcOutcome::App(e),
    }
}

/// Authenticate, then run a mail method with the session. The session must
/// be a mailbox session (admin sessions have no IMAP password).
async fn mail_route<F, Fut>(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
    method: F,
) -> RpcOutcome
where
    F: FnOnce(AppState, Session, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, AppError>>,
{
    let session = match session_of(sessions, ctx, params) {
        Ok(session) => session,
        Err(e) => return RpcOutcome::App(e),
    };
    if session.password.is_none() {
        return RpcOutcome::App(AppError::new(
            "Session.Required",
            "mailbox session required",
        ));
    }
    wrap_result(method(app.clone(), session, params.clone()).await)
}

fn login(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
) -> Result<Value, AppError> {
    let address = required(params, "address")?;
    let password = required(params, "password")?;
    match sessions.login(app.store.as_ref(), &address, &password) {
        Ok((token, session)) => {
            ctx.token = Some(token.clone());
            Ok(json!({
                "token": token,
                "address": session.address.as_str(),
                "display_name": session.display_name,
            }))
        }
        Err(LoginError::UnknownAccount | LoginError::InvalidCredentials) => Err(AppError::new(
            "Session.InvalidCredentials",
            "address or password is wrong",
        )),
    }
}

fn admin_login(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
) -> Result<Value, AppError> {
    let token = required(params, "token")?;
    match sessions.admin_login(app.config.admin_token.as_deref(), &token) {
        Ok((token, session)) => {
            ctx.token = Some(token.clone());
            Ok(json!({ "ok": true, "token": token, "admin": session.admin }))
        }
        Err(_) => Err(AppError::new(
            "Session.InvalidCredentials",
            "admin token is wrong",
        )),
    }
}

fn session_of(
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
) -> Result<Session, AppError> {
    let token = token_of(params)
        .or_else(|| ctx.token.clone())
        .ok_or_else(|| AppError::new("Session.Required", "login first"))?;
    let session = sessions
        .resolve(&token)
        .map_err(|_| AppError::new("Session.Required", "session expired or unknown"))?;
    ctx.token = Some(token);
    Ok(session)
}

fn require_admin(
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
) -> Result<(), AppError> {
    if session_of(sessions, ctx, params)?.admin {
        Ok(())
    } else {
        Err(AppError::new("Admin.Forbidden", "admin session required"))
    }
}

fn token_of(params: &Value) -> Option<String> {
    str_param(params, "token")
}

fn str_param(params: &Value, key: &str) -> Option<String> {
    params.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn required(params: &Value, key: &str) -> Result<String, AppError> {
    str_param(params, key)
        .ok_or_else(|| AppError::new("Session.MalformedParams", format!("{key} is required")))
}

// ── mail methods ──────────────────────────────────────────────────────────

fn imap_of(app: &AppState) -> Result<Imap, AppError> {
    app.config
        .imap
        .parse()
        .map(Imap::new)
        .map_err(|e| AppError::new("Mail.ImapUnavailable", format!("{}: {e}", app.config.imap)))
}

fn submission_of(app: &AppState) -> Result<Submission, AppError> {
    app.config
        .submission
        .parse()
        .map(Submission::new)
        .map_err(|e| {
            AppError::new(
                "Mail.SubmissionUnavailable",
                format!("{}: {e}", app.config.submission),
            )
        })
}

async fn mail_list(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let mailbox = params
        .get("mailbox")
        .and_then(Value::as_str)
        .unwrap_or("INBOX")
        .to_owned();
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 200) as usize;
    let password = session.password.as_deref().expect("checked at route");
    let rows = imap_of(&app)?
        .list(session.address.as_str(), password, &mailbox, limit)
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    Ok(json!({ "mailbox": mailbox, "messages": rows }))
}

async fn mail_read(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let uid = params
        .get("uid")
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::new("Mail.MalformedParams", "uid is required"))?
        as u32;
    let mailbox = params
        .get("mailbox")
        .and_then(Value::as_str)
        .unwrap_or("INBOX")
        .to_owned();
    let mark_seen = if params.get("markSeen").and_then(Value::as_bool) == Some(false) {
        MarkSeen::No
    } else {
        MarkSeen::Yes
    };
    let password = session.password.as_deref().expect("checked at route");
    let raw = imap_of(&app)?
        .fetch_raw(session.address.as_str(), password, &mailbox, uid, mark_seen)
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    let parsed = ayane_mail::mime::parse(&raw)
        .ok_or_else(|| AppError::new("Mail.Unparsable", "the message could not be parsed"))?;
    let links = ayane_mail::phishing::analyze(parsed.text.as_deref(), parsed.html.as_deref());
    Ok(json!({ "uid": uid, "mailbox": mailbox, "message": parsed, "links": links }))
}

async fn mail_send(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let to = required(&params, "to")?;
    let subject = params
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let body = params
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let to = ayane_proto::Address::parse(&to)
        .map_err(|e| AppError::new("Mail.BadRecipient", e.to_string()))?;
    let password = session.password.as_deref().expect("checked at route");
    let message = ayane_mail::compose::build_plain_message(
        &session.address,
        &session.display_name,
        &to,
        &subject,
        &body,
    )
    .map_err(|e| AppError::new("Mail.ComposerRejected", e.to_string()))?;
    submission_of(&app)?
        .send(session.address.as_str(), password, message.clone())
        .await
        .map_err(|e| AppError::new("Mail.SubmissionFailed", e.to_string()))?;
    // Best-effort Sent copy; a failure to append must not fail the send.
    if let Ok(imap) = imap_of(&app) {
        let _ = imap
            .append_to_mailbox(
                session.address.as_str(),
                password,
                "Sent",
                &ayane_mail::compose::render(&message),
            )
            .await;
    }
    Ok(json!({ "queued": true, "to": to.as_str() }))
}

async fn mail_mark_seen(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let uid = params
        .get("uid")
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::new("Mail.MalformedParams", "uid is required"))?
        as u32;
    let mailbox = params
        .get("mailbox")
        .and_then(Value::as_str)
        .unwrap_or("INBOX")
        .to_owned();
    let unseen = params.get("seen").and_then(Value::as_bool) == Some(false);
    let password = session.password.as_deref().expect("checked at route");
    // Reuse fetch_raw with peek semantics; flag changes ride STORE via the
    // same session shape (a dedicated store call keeps this honest).
    let imap = imap_of(&app)?;
    if unseen {
        imap.store_flag(
            session.address.as_str(),
            password,
            &mailbox,
            uid,
            "-FLAGS.SILENT (\\Seen)",
        )
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    } else {
        imap.store_flag(
            session.address.as_str(),
            password,
            &mailbox,
            uid,
            "+FLAGS.SILENT (\\Seen)",
        )
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    }
    Ok(json!({ "ok": true }))
}

// ── admin methods (mirroring the REST surface) ────────────────────────────

fn load_state(app: &AppState) -> Value {
    app.store
        .load()
        .map(|stored| serde_json::to_value(stored.desired).unwrap_or(Value::Null))
        .unwrap_or(Value::Null)
}

async fn put_state(app: &AppState, params: &Value) -> Result<Value, AppError> {
    let body: PutState = serde_json::from_value(params.clone())
        .map_err(|e| AppError::new("Admin.MalformedState", e.to_string()))?;
    let ack = crate::api::put_state_impl(app, body)
        .await
        .map_err(|e| AppError::new("Admin.StateRejected", e.prose()))?;
    serde_json::to_value(ack).map_err(|e| AppError::new("Admin.StateRejected", e.to_string()))
}

async fn do_apply(app: &AppState) -> Result<Value, AppError> {
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let report = apply::apply(&app.config.state_dir, &stored, app.driver.clone())
        .await
        .map_err(|e| AppError::new("Admin.ApplyFailed", e.to_string()))?;
    serde_json::to_value(report).map_err(|e| AppError::new("Admin.ApplyFailed", e.to_string()))
}
