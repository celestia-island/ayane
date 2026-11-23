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
            Ok(session) => {
                let admin = sessions.is_admin(app.store.as_ref(), &session);
                RpcOutcome::Result(json!({
                    "address": session.address.as_str(),
                    "display_name": session.display_name,
                    "admin": admin,
                }))
            }
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
        "mail.listStarred" => mail_route(app, sessions, ctx, &params, mail_list_starred).await,
        "mail.read" => mail_route(app, sessions, ctx, &params, mail_read).await,
        "mail.send" => mail_route(app, sessions, ctx, &params, mail_send).await,
        "mail.saveDraft" => mail_route(app, sessions, ctx, &params, mail_save_draft).await,
        "mail.markSeen" => mail_route(app, sessions, ctx, &params, mail_mark_seen).await,
        "mail.star" => mail_route(app, sessions, ctx, &params, mail_star).await,
        "mail.trash" => mail_route(app, sessions, ctx, &params, mail_trash).await,
        "mail.purge" => mail_route(app, sessions, ctx, &params, mail_purge).await,
        "mail.fromAddresses" => mail_route(app, sessions, ctx, &params, mail_from_addresses).await,
        "mail.templates.list" => mail_route(app, sessions, ctx, &params, mail_templates_list).await,
        "mail.templates.save" => mail_route(app, sessions, ctx, &params, mail_templates_save).await,
        "mail.templates.delete" => {
            mail_route(app, sessions, ctx, &params, mail_templates_delete).await
        }
        "admin.state.get" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => RpcOutcome::Result(load_state(app)),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.state.put" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(put_state(app, &params).await),
            Err(e) => RpcOutcome::App(e),
        },
        "dns.check" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(dns_check(app, &params).await),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.apply" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(do_apply(app).await),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.net.cert" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(net_cert(app).await),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.net.traffic" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(net_traffic(app, params.clone()).await),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.audit.run" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(audit_run(app, sessions, ctx, params.clone()).await),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.mcp.get" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(mcp_get(app)),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.mcp.put" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(mcp_put(app, params.clone())),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.accounts.setAdmin" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(set_account_admin(app, &params)),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.policy.get" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(policy_get(app)),
            Err(e) => RpcOutcome::App(e),
        },
        "admin.policy.put" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(policy_put(app, params.clone())),
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
                "admin": session.admin,
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
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
) -> Result<(), AppError> {
    let session = session_of(sessions, ctx, params)?;
    // Live account lookup: an admin grant (or its withdrawal) applies to
    // sessions already open.
    if sessions.is_admin(app.store.as_ref(), &session) {
        Ok(())
    } else {
        Err(AppError::new("Admin.Forbidden", "admin account required"))
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
    let (identity, password, _) = resolve_read_identity(&app, &session, identity_of(&params))?;
    let listing = imap_of(&app)?
        .list(identity.as_str(), password.as_str(), &mailbox, limit)
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    Ok(json!({
        "mailbox": mailbox,
        "total": listing.total,
        "unread": listing.unread,
        "messages": listing.messages,
    }))
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
    let (identity, password, _) = resolve_read_identity(&app, &session, identity_of(&params))?;
    let raw = imap_of(&app)?
        .fetch_raw(
            identity.as_str(),
            password.as_str(),
            &mailbox,
            uid,
            mark_seen,
        )
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

    // Send identity: the session's own address, or a shared mailbox this
    // account belongs to (the From picker's 公共信箱 entries).
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let (from_address, from_name) = resolve_send_identity(
        &stored,
        &session,
        params.get("from").and_then(Value::as_str),
    )?;

    // Attachments arrive base64-encoded; the size cap keeps one request
    // from carrying an unreasonable payload (the engine queue handles the
    // real limits).
    use base64::Engine as _;
    let mut attachments = Vec::new();
    let mut total_attachment_bytes = 0usize;
    if let Some(list) = params.get("attachments").and_then(Value::as_array) {
        for item in list {
            let filename = item
                .get("filename")
                .and_then(Value::as_str)
                .unwrap_or("attachment")
                .to_owned();
            let content_type = item
                .get("content_type")
                .and_then(Value::as_str)
                .unwrap_or("application/octet-stream")
                .to_owned();
            let data = item
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::new("Mail.MalformedParams", "attachment data required"))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| {
                    AppError::new("Mail.MalformedParams", format!("attachment base64: {e}"))
                })?;
            if bytes.len() > 10 * 1024 * 1024 {
                return Err(AppError::new(
                    "Mail.MalformedParams",
                    "attachment exceeds 10 MiB",
                ));
            }
            total_attachment_bytes += bytes.len();
            if total_attachment_bytes > 25 * 1024 * 1024 {
                return Err(AppError::new(
                    "Mail.MalformedParams",
                    "attachments exceed 25 MiB in total",
                ));
            }
            attachments.push(ayane_mail::compose::OutgoingAttachment {
                filename,
                content_type,
                data: bytes,
            });
        }
    }

    let message = if attachments.is_empty()
        && params.get("format").and_then(Value::as_str) != Some("markdown")
    {
        ayane_mail::compose::build_plain_message(&from_address, &from_name, &to, &subject, &body)
            .map_err(|e| AppError::new("Mail.ComposerRejected", e.to_string()))?
    } else {
        ayane_mail::compose::build_composed_message(
            &from_address,
            &from_name,
            &to,
            &subject,
            &body,
            &attachments,
        )
        .map_err(|e| AppError::new("Mail.ComposerRejected", e.to_string()))?
    };
    // SASL authenticates as the LOGIN account (its password proves it);
    // the chosen identity only becomes the envelope sender and the From
    // header. Authenticating as the shared address would need the machine
    // credential, which Postfix SASL does not know about.
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
                Some("\\Seen"),
                &ayane_mail::compose::render(&message),
            )
            .await;
    }
    // Sending a DRAFT retires the draft copy (best effort, like the Sent
    // copy — a failed cleanup must not fail an already-queued send).
    if let Some(draft_uid) = params.get("draftUid").and_then(Value::as_u64) {
        if let Ok(imap) = imap_of(&app) {
            let _ = imap
                .purge_message(
                    session.address.as_str(),
                    password,
                    "Drafts",
                    draft_uid as u32,
                )
                .await;
        }
    }
    Ok(json!({ "queued": true, "to": to.as_str() }))
}

/// Save the composer's current state as a DRAFT: build the message with
/// draft semantics (the recipient may be half-typed) and APPEND it to the
/// Drafts mailbox, which is autocreated like every folder the webmail
/// touches.
async fn mail_save_draft(
    app: AppState,
    session: Session,
    params: Value,
) -> Result<Value, AppError> {
    let to = params
        .get("to")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
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
    let (identity, password, display) =
        resolve_read_identity(&app, &session, identity_of(&params))?;
    let message =
        ayane_mail::compose::build_draft_message(&identity, &display, &to, &subject, &body)
            .map_err(|e| AppError::new("Mail.ComposerRejected", e.to_string()))?;
    let imap = imap_of(&app)?;
    imap.append_to_mailbox(
        identity.as_str(),
        password.as_str(),
        "Drafts",
        None,
        &ayane_mail::compose::render(&message),
    )
    .await
    .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    Ok(json!({ "saved": true }))
}

/// The 已加星标 roster: flagged messages across the user's real folders,
/// merged newest first. A flag is per-message — there is no Starred folder.
async fn mail_list_starred(
    app: AppState,
    session: Session,
    params: Value,
) -> Result<Value, AppError> {
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 200) as usize;
    let (identity, password, _) = resolve_read_identity(&app, &session, identity_of(&params))?;
    let rows = imap_of(&app)?
        .list_flagged(
            identity.as_str(),
            password.as_str(),
            &["INBOX", "Sent", "Drafts"],
            limit,
        )
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    let total = rows.len() as u32;
    Ok(json!({ "mailbox": "Starred", "total": total, "messages": rows }))
}

/// Toggle the `\Flagged` (star) flag on one message.
async fn mail_star(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let uid = uid_of(&params)?;
    let mailbox = mailbox_of(&params, "INBOX");
    let starred = params.get("starred").and_then(Value::as_bool) != Some(false);
    let (identity, password, _) = resolve_read_identity(&app, &session, identity_of(&params))?;
    let op = if starred {
        "+FLAGS.SILENT (\\Flagged)"
    } else {
        "-FLAGS.SILENT (\\Flagged)"
    };
    imap_of(&app)?
        .store_flag(identity.as_str(), password.as_str(), &mailbox, uid, op)
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    Ok(json!({ "ok": true, "starred": starred }))
}

/// Delete one message: MOVE it to the auto-created Trash mailbox. Refused
/// for messages already in Trash — permanent deletion there is `mail.purge`
/// behind a confirm.
async fn mail_trash(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let uid = uid_of(&params)?;
    let mailbox = mailbox_of(&params, "INBOX");
    if mailbox == "Trash" {
        return Err(AppError::new(
            "Mail.MalformedParams",
            "already in Trash: use mail.purge",
        ));
    }
    let (identity, password, _) = resolve_read_identity(&app, &session, identity_of(&params))?;
    imap_of(&app)?
        .move_to_mailbox(identity.as_str(), password.as_str(), &mailbox, uid, "Trash")
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    Ok(json!({ "ok": true }))
}

/// Permanently delete one message from Trash (STORE \Deleted + EXPUNGE —
/// only this message carries the flag).
async fn mail_purge(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let uid = uid_of(&params)?;
    let mailbox = mailbox_of(&params, "Trash");
    let (identity, password, _) = resolve_read_identity(&app, &session, identity_of(&params))?;
    imap_of(&app)?
        .purge_message(identity.as_str(), password.as_str(), &mailbox, uid)
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    Ok(json!({ "ok": true }))
}

/// The `uid` param (a required positive integer) as u32.
fn uid_of(params: &Value) -> Result<u32, AppError> {
    params
        .get("uid")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0 && *v <= u32::MAX as u64)
        .map(|v| v as u32)
        .ok_or_else(|| AppError::new("Mail.MalformedParams", "uid is required"))
}

/// The `mailbox` param with a fallback (every folder the webmail names).
fn mailbox_of(params: &Value, fallback: &str) -> String {
    params
        .get("mailbox")
        .and_then(Value::as_str)
        .filter(|m| !m.trim().is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

/// The `as` param (the mailbox identity), treated as absent when empty:
/// the webui forwards the header picker's value on every call, and "" is
/// its "identity list not resolved yet" state — not a request for a
/// mailbox named "".
fn identity_of(params: &Value) -> Option<&str> {
    params
        .get("as")
        .and_then(Value::as_str)
        .filter(|identity| !identity.trim().is_empty())
}

// ── send identities + templates ───────────────────────────────────────────

/// Every address the session may send as: the account's own address plus
/// every shared mailbox it is a member of (公共信箱). The composer's From
/// picker — personal vs shared identities in one list.
async fn mail_from_addresses(
    app: AppState,
    session: Session,
    _params: Value,
) -> Result<Value, AppError> {
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let mut identities = vec![json!({
        "address": session.address.as_str(),
        "display_name": session.display_name,
        "kind": "personal",
    })];
    if let Some(account) = stored
        .desired
        .accounts
        .iter()
        .find(|account| account.address == session.address)
    {
        for shared in &stored.desired.shared {
            if shared.members.contains(&account.id) {
                identities.push(json!({
                    "address": shared.address.as_str(),
                    "display_name": shared.address.local().to_owned(),
                    "kind": "shared",
                }));
            }
        }
    }
    Ok(json!({ "identities": identities }))
}

/// Resolve the mailbox identity a mail operation runs against: the
/// session's own address by default, or a shared mailbox the account is a
/// member of (reading it logs into IMAP with the server-minted machine
/// credential — the member never sees it).
///
/// Returns the address to open, the IMAP password to use and a display name.
fn resolve_read_identity(
    app: &AppState,
    session: &Session,
    requested: Option<&str>,
) -> Result<(ayane_proto::Address, String, String), AppError> {
    let own = session.address.clone();
    let password = session.password.clone().unwrap_or_default();
    let Some(requested) = requested else {
        return Ok((own, password, session.display_name.clone()));
    };
    if requested == own.as_str() {
        return Ok((own, password, session.display_name.clone()));
    }
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let parsed = ayane_proto::Address::parse(requested)
        .map_err(|e| AppError::new("Mail.BadRecipient", e.to_string()))?;
    let Some(account) = stored
        .desired
        .accounts
        .iter()
        .find(|account| account.address == session.address)
    else {
        return Err(AppError::new("Mail.BadRecipient", "unknown account"));
    };
    let member = stored
        .desired
        .shared
        .iter()
        .any(|shared| shared.address == parsed && shared.members.contains(&account.id));
    if !member {
        return Err(AppError::new(
            "Mail.BadRecipient",
            "that shared mailbox does not belong to this account",
        ));
    }
    let shared_password = app
        .store
        .shared_imap_password(parsed.as_str())
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let display = parsed.local().to_owned();
    Ok((parsed, shared_password, display))
}

/// Validate a requested send identity: the session's own address or a
/// shared mailbox it belongs to. Returns the display name for the header.
fn resolve_send_identity(
    stored: &ayane_store::StoredState,
    session: &Session,
    requested: Option<&str>,
) -> Result<(ayane_proto::Address, String), AppError> {
    let own = session.address.clone();
    let Some(requested) = requested else {
        return Ok((own, session.display_name.clone()));
    };
    if requested == own.as_str() {
        return Ok((own, session.display_name.clone()));
    }
    let parsed = ayane_proto::Address::parse(requested)
        .map_err(|e| AppError::new("Mail.BadRecipient", e.to_string()))?;
    let Some(account) = stored
        .desired
        .accounts
        .iter()
        .find(|account| account.address == session.address)
    else {
        return Err(AppError::new(
            "Mail.BadRecipient",
            "unknown sending account",
        ));
    };
    let member = stored
        .desired
        .shared
        .iter()
        .any(|shared| shared.address == parsed && shared.members.contains(&account.id));
    if !member {
        return Err(AppError::new(
            "Mail.BadRecipient",
            "that shared mailbox does not belong to this account",
        ));
    }
    let display = parsed.local().to_owned();
    Ok((parsed, display))
}

async fn mail_templates_list(
    app: AppState,
    session: Session,
    _params: Value,
) -> Result<Value, AppError> {
    let templates = app
        .store
        .list_templates(session.address.as_str())
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    Ok(json!({ "templates": templates }))
}

async fn mail_templates_save(
    app: AppState,
    session: Session,
    params: Value,
) -> Result<Value, AppError> {
    let name = required(&params, "name")?;
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
    let id = params
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let template = ayane_store::Template {
        id,
        owner: session.address.as_str().to_owned(),
        name,
        subject,
        body,
    };
    app.store
        .save_template(&template)
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    Ok(json!({ "saved": true, "id": template.id }))
}

async fn mail_templates_delete(
    app: AppState,
    session: Session,
    params: Value,
) -> Result<Value, AppError> {
    let id = required(&params, "id")?;
    app.store
        .delete_template(session.address.as_str(), &id)
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    Ok(json!({ "ok": true }))
}

/// Flip one account's administrator grant WITHOUT touching its password
/// (the whole-state PUT would demand every password; a role change is not
/// a credential change).
fn set_account_admin(app: &AppState, params: &Value) -> Result<Value, AppError> {
    let address = required(params, "address")?;
    let address = ayane_proto::Address::parse(&address)
        .map_err(|e| AppError::new("Admin.MalformedState", e.to_string()))?;
    let admin = params.get("admin").and_then(Value::as_bool) == Some(true);
    let mut stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let mut found = false;
    for account in &mut stored.desired.accounts {
        if account.address == address {
            account.admin = admin;
            found = true;
        }
    }
    if !found {
        return Err(AppError::new("Admin.MalformedState", "no such account"));
    }
    stored
        .desired
        .validate()
        .map_err(|e| AppError::new("Admin.StateRejected", e.to_string()))?;
    app.store
        .save(&stored)
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    Ok(json!({ "saved": true, "address": address.as_str(), "admin": admin }))
}

// ── network surface ───────────────────────────────────────────────────────

/// The deployed TLS certificate's status (leaf validity from the PEM chain
/// the engine serves).
async fn net_cert(app: &AppState) -> Result<Value, AppError> {
    let path = app.config.cert_file.as_deref().ok_or_else(|| {
        AppError::new("Admin.MalformedState", "AYANE_CERT_FILE is not configured")
    })?;
    let status = crate::net::cert_status(path)
        .map_err(|e| AppError::new("Admin.MalformedState", e.to_string()))?;
    Ok(serde_json::to_value(status).unwrap_or(json!({})))
}

/// Postfix traffic of the recent window (default 72h): inbound connect
/// peers and outbound relay deliveries, aggregated from the engine logs.
async fn net_traffic(app: &AppState, params: Value) -> Result<Value, AppError> {
    let since = params
        .get("since")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("72h")
        .to_owned();
    let lines = app
        .driver
        .postfix_logs(&since)
        .map_err(|e| AppError::new("Admin.ApplyFailed", e))?;
    let report = crate::net::traffic_from_lines(&lines);
    Ok(serde_json::to_value(report).unwrap_or(json!({})))
}

/// The sender policy slices the 黑白名单 page edits.
fn policy_get(app: &AppState) -> Result<Value, AppError> {
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    fn rules(list: &[ayane_proto::SenderRule]) -> Vec<String> {
        list.iter()
            .map(|rule| match rule {
                ayane_proto::SenderRule::Address(a) => a.as_str().to_owned(),
                ayane_proto::SenderRule::Domain(d) => format!("@{d}"),
            })
            .collect()
    }
    Ok(json!({
        "allowlist": rules(&stored.desired.policy.allowlist),
        "denylist": rules(&stored.desired.policy.denylist),
    }))
}

fn policy_put(app: &AppState, params: Value) -> Result<Value, AppError> {
    fn parse_rules(params: &Value, key: &str) -> Result<Vec<ayane_proto::SenderRule>, AppError> {
        let mut rules = Vec::new();
        let Some(raw) = params.get(key).and_then(Value::as_array) else {
            return Err(AppError::new(
                "Admin.MalformedState",
                format!("{key} must be a list"),
            ));
        };
        for item in raw {
            let Some(text) = item.as_str() else {
                return Err(AppError::new(
                    "Admin.MalformedState",
                    "rules must be strings",
                ));
            };
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            if let Some(domain) = text.strip_prefix('@') {
                // The renderer interpolates the domain into a postfix
                // access map — anything but DNS characters would be a
                // line injection.
                ayane_proto::check_domain(domain).map_err(|e| {
                    AppError::new("Admin.MalformedState", format!("invalid domain rule: {e}"))
                })?;
                rules.push(ayane_proto::SenderRule::Domain(domain.to_ascii_lowercase()));
            } else {
                let address = ayane_proto::Address::parse(text).map_err(|e| {
                    AppError::new("Admin.MalformedState", format!("invalid sender rule: {e}"))
                })?;
                rules.push(ayane_proto::SenderRule::Address(address));
            }
        }
        Ok(rules)
    }
    let allowlist = parse_rules(&params, "allowlist")?;
    let denylist = parse_rules(&params, "denylist")?;
    let mut stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    stored.desired.policy.allowlist = allowlist;
    stored.desired.policy.denylist = denylist;
    stored
        .desired
        .validate()
        .map_err(|e| AppError::new("Admin.StateRejected", e.to_string()))?;
    app.store
        .save(&stored)
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    Ok(json!({ "saved": true, "note": "apply to reload the engine" }))
}

// ── audit (keyword + arona AI) ────────────────────────────────────────────

/// One flagged message from an audit pass.
#[derive(serde::Serialize)]
struct AuditHit {
    uid: u32,
    subject: Option<String>,
    from: Option<String>,
    /// The keyword that matched (keyword leg).
    #[serde(skip_serializing_if = "Option::is_none")]
    keyword: Option<String>,
    /// Truncated body text for the AI leg (never serialized to clients).
    #[serde(skip_serializing)]
    snippet: String,
    /// The AI verdict (arona leg): the model's one-line reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_verdict: Option<String>,
}

/// Scan the INBOX's recent messages against the configured keyword list,
/// then (when enabled) ask arona to classify each hit. AI goes ONLY through
/// the org's arona panel — no other provider is wired.
async fn audit_run(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: Value,
) -> Result<Value, AppError> {
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .clamp(1, 50) as usize;
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let audit = &stored.desired.audit;
    if !audit.enabled {
        return Err(AppError::new(
            "Admin.MalformedState",
            "audit is disabled in the configuration",
        ));
    }
    let keywords: Vec<String> = audit
        .keywords
        .iter()
        .map(|k| k.to_ascii_lowercase())
        .collect();

    // The session reading the mail: audit runs under the admin session that
    // called it (their INBOX is the surface being audited).
    let session = session_of(sessions, ctx, &params)?;
    let password = session.password.as_deref().ok_or_else(|| {
        AppError::new(
            "Session.Required",
            "the admin session has no mail credentials",
        )
    })?;

    let listing = imap_of(app)?
        .list(session.address.as_str(), password, "INBOX", limit)
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;

    let mut hits: Vec<AuditHit> = Vec::new();
    for row in &listing.messages {
        let Ok(raw) = imap_of(app)?
            .fetch_raw(
                session.address.as_str(),
                password,
                "INBOX",
                row.uid,
                ayane_mail::client::MarkSeen::No,
            )
            .await
        else {
            continue;
        };
        let Some(parsed) = ayane_mail::mime::parse(&raw) else {
            continue;
        };
        let haystack = format!(
            "{}\n{}\n{}",
            parsed.subject.as_deref().unwrap_or(""),
            parsed.text.as_deref().unwrap_or(""),
            parsed.html.as_deref().unwrap_or(""),
        )
        .to_ascii_lowercase();
        if let Some(keyword) = keywords
            .iter()
            .find(|k| !k.is_empty() && haystack.contains(k.as_str()))
        {
            hits.push(AuditHit {
                uid: row.uid,
                subject: parsed.subject.clone(),
                from: parsed.from.clone(),
                keyword: Some(keyword.clone()),
                snippet: parsed
                    .text
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(800)
                    .collect(),
                ai_verdict: None,
            });
        }
    }

    // The AI leg: arona classifies each keyword hit (cheaper than scanning
    // everything, and the keyword leg already names the suspects).
    let ai = &stored.desired.audit.ai;
    let scanned = hits.len();
    if ai.enabled && !hits.is_empty() && !ai.endpoint.trim().is_empty() {
        let client = reqwest::Client::new();
        for hit in &mut hits {
            let prompt = format!(
                "You are a mail security auditor. Decide whether the following message is suspicious (phishing, fraud, malware lure, policy violation) or benign. Reply with EXACTLY one line: SUSPICIOUS: <reason> or BENIGN: <reason>.\n\nSubject: {}\nBody snippet: {}",
                hit.subject.as_deref().unwrap_or(""),
                hit.snippet,
            );
            let reply = client
                .post(format!(
                    "{}/v1/chat/completions",
                    ai.endpoint.trim_end_matches('/')
                ))
                .bearer_auth(&ai.api_token)
                .json(&serde_json::json!({
                    "model": ai.model,
                    "messages": [{ "role": "user", "content": prompt }],
                }))
                .send()
                .await;
            let verdict = match reply {
                Ok(resp) if resp.status().is_success() => {
                    let body: serde_json::Value =
                        resp.json().await.unwrap_or(serde_json::Value::Null);
                    body.pointer("/choices/0/message/content")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                }
                _ => None,
            };
            hit.ai_verdict = verdict;
        }
    }

    Ok(json!({ "scanned": listing.messages.len(), "flagged": scanned, "hits": hits }))
}

// ── MCP surface configuration ─────────────────────────────────────────────

/// The MCP proxy's configured surface. The token is returned to the admin
/// surface only (the page shows it behind an explicit reveal).
fn mcp_get(app: &AppState) -> Result<Value, AppError> {
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    Ok(json!({
        "tools": stored.desired.mcp.tools,
        "hasToken": !stored.desired.mcp.token.is_empty(),
    }))
}

fn mcp_put(app: &AppState, params: Value) -> Result<Value, AppError> {
    let tools: Vec<String> = params
        .get("tools")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let rotate = params.get("rotateToken").and_then(Value::as_bool) == Some(true);
    let mut stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    stored.desired.mcp.tools = tools;
    let minted = if rotate {
        let raw =
            uuid::Uuid::new_v4().simple().to_string() + &uuid::Uuid::new_v4().simple().to_string();
        stored.desired.mcp.token = raw.clone();
        Some(raw)
    } else {
        None
    };
    app.store
        .save(&stored)
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    // The token is shown once, on the rotation reply — exactly like the
    // family's client-secret reveals.
    Ok(json!({ "saved": true, "token": minted }))
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
    let (identity, password, _) = resolve_read_identity(&app, &session, identity_of(&params))?;
    // Reuse fetch_raw with peek semantics; flag changes ride STORE via the
    // same session shape (a dedicated store call keeps this honest).
    let imap = imap_of(&app)?;
    let op = if unseen {
        "-FLAGS.SILENT (\\Seen)"
    } else {
        "+FLAGS.SILENT (\\Seen)"
    };
    imap.store_flag(identity.as_str(), password.as_str(), &mailbox, uid, op)
        .await
        .map_err(|e| AppError::new("Mail.ImapFailed", e.to_string()))?;
    Ok(json!({ "ok": true }))
}

// ── admin methods (mirroring the REST surface) ────────────────────────────

fn load_state(app: &AppState) -> Value {
    app.store
        .load()
        .map(|stored| redact_state(serde_json::to_value(stored.desired).unwrap_or(Value::Null)))
        .unwrap_or(Value::Null)
}

/// The placeholder a state read writes where a secret lived. Not a
/// credential — the marker a write-back recognises to keep the stored one.
pub const REDACTED_SENTINEL: &str = "__redacted__";

/// Strip the state's embedded secrets before any read leaves the process:
/// the MCP token (revealed only once, at rotation) and the arona bearer
/// token never ride an API reply. Absent-slice round-trip keeps PUTs safe.
fn redact_state(mut value: Value) -> Value {
    if let Some(Value::String(token)) = value.pointer_mut("/mcp/token") {
        if !token.is_empty() {
            *token = REDACTED_SENTINEL.to_owned();
        }
    }
    if let Some(Value::String(token)) = value.pointer_mut("/audit/ai/api_token") {
        if !token.is_empty() {
            *token = REDACTED_SENTINEL.to_owned();
        }
    }
    value
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
    let report = apply::apply(
        app.store.as_ref(),
        &app.config.state_dir,
        &stored,
        app.driver.clone(),
    )
    .await
    .map_err(|e| AppError::new("Admin.ApplyFailed", e.to_string()))?;
    serde_json::to_value(report).map_err(|e| AppError::new("Admin.ApplyFailed", e.to_string()))
}

/// `dns.check {domain?}` — live DNS wizard for one hosted domain (or the
/// first one when omitted).
async fn dns_check(app: &AppState, params: &Value) -> Result<Value, AppError> {
    let stored = app
        .store
        .load()
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let domain = params
        .get("domain")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| stored.desired.domains.first().map(|d| d.name.clone()))
        .ok_or_else(|| AppError::new("Dns.NoDomain", "no hosted domain to check"))?;
    let mail_host = format!("mail.{domain}");
    let selector = "ayane";
    let snapshot = crate::dns::snapshot(&domain, &mail_host, selector)
        .await
        .map_err(|e| AppError::new("Dns.ResolverFailed", e))?;
    let checks = crate::dns::verdicts(&snapshot, &domain, &mail_host, selector);
    serde_json::to_value(serde_json::json!({
        "domain": domain,
        "mail_host": mail_host,
        "selector": selector,
        "checks": checks,
    }))
    .map_err(|e| AppError::new("Dns.ResolverFailed", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty `as` is the webui picker's "not resolved yet" state, not
    /// a mailbox request — it must read as absent so the mount-time race
    /// degrades to the personal mailbox instead of a parse error.
    #[test]
    fn empty_identity_param_reads_as_absent() {
        assert_eq!(identity_of(&json!({})), None);
        assert_eq!(identity_of(&json!({ "as": "" })), None);
        assert_eq!(identity_of(&json!({ "as": "  " })), None);
        assert_eq!(
            identity_of(&json!({ "as": "team@example.test" })),
            Some("team@example.test")
        );
    }
}
