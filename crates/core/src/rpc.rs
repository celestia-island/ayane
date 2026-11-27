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
//!
//! That password is also the account's second factor on the privileged
//! surface: a provider-minted session that still owes it
//! (`needs_mailbox_password`) is refused by EVERY `admin.*` method with
//! `Session.MailboxLocked`, the same words the mail methods answer, until
//! `session.unlockMailbox` proves it once — and by the two methods that
//! change the account's linked sign-ins, since those are ways into the
//! account exactly as administration is a way to change it. And every
//! handler that edits a slice of the snapshot does so under the store's
//! lock ([`update_state`](self)): an unlocked read-edit-write writes back a
//! moment that has already passed.

use serde_json::{json, Value};

use ayane_store::StoredState;

use kirino::auth::identity::external::ExternalIdentityStore;

use crate::api::PutState;
use crate::apply;
use crate::auth::{self, AttemptPurpose, AuthError, IdentityLinks};
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
        // The family's login contract: the discovery document the panel
        // renders its channels from — password plus one row per CONFIGURED
        // provider, so an unconfigured provider never shows as a dead option.
        "session.loginPolicy" => RpcOutcome::Result(login_policy(app)),
        "session.login" => wrap(login(app, sessions, ctx, &params)),
        "session.adminLogin" => wrap(admin_login(app, sessions, ctx, &params)),
        // Provider sign-in: start (ticket → href), claim the callback's
        // handoff, prove the mailbox password of a locked session.
        //
        // `oauthBegin` and `unlockMailbox` never see the params object:
        // the few fields each one reads are taken by name HERE, so
        // neither handler can be handed an address — a sign-in aims at no
        // mailbox, and a password is proven for the session's own.
        "session.oauthBegin" => wrap(match required(&params, "provider") {
            Ok(provider) => oauth_begin(app, &provider, str_param(&params, "returnTo")).await,
            Err(refused) => Err(refused),
        }),
        "session.claimHandoff" => wrap(claim_handoff(app, sessions, ctx, &params)),
        "session.unlockMailbox" => wrap(match required(&params, "password") {
            Ok(password) => unlock_mailbox(app, sessions, ctx, token_of(&params), &password),
            Err(refused) => Err(refused),
        }),
        // Linked sign-ins of the authenticated mailbox. Listing is a
        // read; linking and unlinking change the ways into the account
        // and are gated on the mailbox password like every privileged
        // surface.
        "session.identities" => match session_of(sessions, ctx, &params) {
            Ok(session) => wrap_result(list_identities(app, &session).await),
            Err(e) => RpcOutcome::App(e),
        },
        // MUT:locked-no-link-changes
        "session.unlinkIdentity" => {
            match session_of(sessions, ctx, &params).and_then(require_mailbox_unlocked) {
                Ok(session) => wrap_result(unlink_identity(app, &session, &params).await),
                Err(e) => RpcOutcome::App(e),
            }
        }
        // MUT:locked-no-link-changes
        "session.linkIdentity" => {
            match session_of(sessions, ctx, &params).and_then(require_mailbox_unlocked) {
                Ok(session) => wrap_result(link_identity(app, &session, &params).await),
                Err(e) => RpcOutcome::App(e),
            }
        }
        "session.whoami" => match session_of(sessions, ctx, &params) {
            Ok(session) => {
                // MUT:whoami-authority-held — `admin` is the authority the
                // session holds right now (none while the mailbox is
                // locked, the live account table afterwards), never the
                // flag as it stood at mint time.
                let admin = sessions.is_admin(app.store.as_ref(), &session);
                RpcOutcome::Result(json!({
                    "address": session.address.as_str(),
                    "display_name": session.display_name,
                    "admin": admin,
                    "needs_mailbox_password": session.needs_mailbox_password,
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
        // The one domain field nothing else could write: `signers_from_env`
        // signs a domain whose state carries `dkim.selector`, and until this
        // method existed the only way to put one there was to hand-edit the
        // state JSON — which is not a channel a deployment's operator has.
        "admin.domain.dkim.put" => match require_admin(app, sessions, ctx, &params) {
            Ok(()) => wrap_result(domain_dkim_put(app, &params)),
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

/// The refusal every privileged surface answers while the session owes
/// the mailbox password — the mail methods, the admin gate, the audit leg,
/// the linked sign-ins — in the same words, so the SPA has one path to
/// act on.
fn mailbox_locked() -> AppError {
    AppError::new(
        "Session.MailboxLocked",
        "the mailbox is locked: enter the mailbox password",
    )
}

/// Authenticate, then run a mail method with the session. The session must be
/// a mailbox session — one that has proven the account's mailbox password, at
/// login or through the unlock card. The password itself is not consulted
/// here: the read path opens files, and there is nobody left to present it
/// to.
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
    // MUT:mail-locked — a provider-minted session owes the mailbox password;
    // nothing that opens the mailbox may run before it is proven.
    //
    // This is the ONLY factor the mail methods check themselves, and it is
    // the one that matters: `mailbox_locked()` is false only after
    // `session.unlockMailbox` verified the account's password (`needs_mailbox_
    // password` starts true for a provider-minted session and is cleared by
    // that one call). The IMAP era additionally re-proved the password on
    // every connection, because Dovecot asked; the maildir reader has nobody
    // to ask, so the proof stands where it was made — at login or at the
    // unlock card — and not on each request. A session whose password is
    // changed afterwards keeps reading until its TTL, which is the same rule
    // every other authenticated surface here already follows.
    if session.mailbox_locked() {
        return RpcOutcome::App(mailbox_locked());
    }
    // An admin-token session is **not** a mailbox session. It is minted with
    // the synthetic address `admin@localhost` and no password
    // (`SessionStore::admin_login`), and `mailbox_locked()` is false for it
    // because it never owed a mailbox password at all. Without this check it
    // would pass the gate above and reach a reader rooted at
    // `admin@localhost`'s maildir — and `admin.audit.run`, which reads the
    // session's own address, would be reading whatever that resolved to.
    // The mail methods are the mailbox's, so they are the account's: the
    // admin surface is `admin.*`.
    if session.password.is_none() {
        return RpcOutcome::App(AppError::new(
            "Session.Required",
            "mailbox session required",
        ));
    }
    wrap_result(method(app.clone(), session, params.clone()).await)
}

/// `session.loginPolicy` — the discovery document, the same value
/// `GET /api/auth/login-methods` serves.
fn login_policy(app: &AppState) -> Value {
    serde_json::to_value(app.auth.catalog.login_policy()).unwrap_or(Value::Null)
}

/// `session.oauthBegin {provider, returnTo?}`: start a provider SIGN-IN
/// and answer the same-origin `href` the browser navigates to.
///
/// Always the login purpose. The handler is handed the provider and the
/// landing path and nothing else — it never sees the params object, so it
/// reads no token (not from the params, not from the connection) and no
/// address — and the method means the same thing on the login page, on a
/// connection that happens to hold a session, and on the agent surface.
/// The sign-in lands on `returnTo`, sanitised to a same-origin path; a
/// foreign address is dropped, never forwarded. Linking an identity to
/// the signed-in mailbox is [`link_identity`]'s job alone.
async fn oauth_begin(
    app: &AppState,
    provider: &str,
    return_to: Option<String>,
) -> Result<Value, AppError> {
    // MUT:oauth-begin-always-login — the purpose is this method's, never
    // inferred from a token that may be lying around: a session on the
    // connection (or in the params) does not turn a sign-in into a link.
    // MUT:oauth-begin-no-address-channel — nor from an address in the
    // params: it names no mailbox to link the identity to. The dispatcher
    // reads `provider` and `returnTo` and passes this function nothing
    // else, so there is no such channel left to read.
    let purpose = AttemptPurpose::Login {
        return_to: auth::safe_return_to(&app.auth.catalog, return_to.as_deref()),
    };
    let href = auth::begin(app, provider, purpose)
        .await
        .map_err(|e| oauth_error(provider, e))?;
    Ok(json!({ "href": href }))
}

/// `session.linkIdentity {provider}` (authenticated, mailbox unlocked):
/// start a link sign-in for the session's mailbox; answers the `href` to
/// navigate to. The one door into `AttemptPurpose::Link`.
async fn link_identity(
    app: &AppState,
    session: &Session,
    params: &Value,
) -> Result<Value, AppError> {
    let provider = required(params, "provider")?;
    let href = auth::begin(
        app,
        &provider,
        AttemptPurpose::Link {
            address: session.address.clone(),
        },
    )
    .await
    .map_err(|e| oauth_error(&provider, e))?;
    Ok(json!({ "href": href }))
}

/// The application error of a sign-in that could not start.
fn oauth_error(provider: &str, e: AuthError) -> AppError {
    match e {
        AuthError::UnknownProvider(_) => AppError::new(
            "Session.OAuthProviderUnknown",
            format!("provider {provider} is not offered here"),
        ),
        AuthError::NotConfigured => AppError::new(
            "Session.OAuthUnavailable",
            "provider sign-in is not configured on this deployment",
        ),
        other => AppError::new("Session.OAuthFailed", other.to_string()),
    }
}

/// `session.claimHandoff {code}` — redeem, exactly once, the sign-in the
/// callback parked. Same shape as `session.login`, plus
/// `needs_mailbox_password` (the verify card follows) and `return_to`.
///
/// `admin` is the authority the session holds, as in every other reply:
/// `false` while the mailbox password is still owed, whatever the
/// account's flag says.
fn claim_handoff(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
) -> Result<Value, AppError> {
    let code = required(params, "code")?;
    // MUT:handoff-one-time — a spent or unknown code mints nothing.
    let handoff = app.auth.attempts.take_handoff(&code).ok_or_else(|| {
        AppError::new(
            "Session.HandoffInvalid",
            "the sign-in handoff is unknown, spent or expired",
        )
    })?;
    let (token, session) = sessions
        .mint_provider(
            handoff.address,
            handoff.display_name,
            handoff.admin,
            handoff.credential,
        )
        .map_err(|_| AppError::new("Session.InvalidCredentials", "session could not be minted"))?;
    ctx.token = Some(token.clone());
    // MUT:whoami-authority-held — the authority the session holds, as
    // `session.whoami` answers it: none while the mailbox password is
    // still owed, whatever the account's flag says.
    let admin = sessions.is_admin(app.store.as_ref(), &session);
    Ok(json!({
        "token": token,
        "address": session.address.as_str(),
        "display_name": session.display_name,
        "admin": admin,
        "needs_mailbox_password": session.needs_mailbox_password,
        "return_to": handoff.return_to,
    }))
}

/// `session.unlockMailbox {password}` — prove the mailbox password of a
/// locked (provider-minted) session; wrong passwords are refused and leave
/// it locked.
///
/// MUT:unlock-own-address — the password is verified against the hash of
/// the SESSION's own mailbox (inside [`SessionStore::unlock_mailbox`]).
/// The dispatcher hands this handler a password and a token and nothing
/// else: there is no address here to read, so no other mailbox's password
/// can ever be the thing that is proven, and a password that belongs to
/// somebody else answers exactly as a wrong one does.
fn unlock_mailbox(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    token: Option<String>,
    password: &str,
) -> Result<Value, AppError> {
    // The token of the params, else the connection's; pinned on the
    // connection from here on.
    session_for(sessions, ctx, token)?;
    let token = ctx.token.clone().expect("set by session_for");
    let unlocked = match sessions.unlock_mailbox(app.store.as_ref(), &token, password) {
        Ok(unlocked) => unlocked,
        Err(LoginError::NotLocked) => {
            return Err(AppError::new(
                "Session.MailboxNotLocked",
                "this session owes no mailbox password",
            ));
        }
        Err(LoginError::UnknownAccount | LoginError::InvalidCredentials) => {
            return Err(AppError::new(
                "Session.InvalidCredentials",
                "mailbox password is wrong",
            ));
        }
    };
    Ok(json!({
        "ok": true,
        "address": unlocked.address.as_str(),
        "display_name": unlocked.display_name,
        // MUT:whoami-authority-held — what the unlock bought, in the same
        // words as every other reply that carries `admin`: the authority
        // the session holds now (read live), not the flag as it stood
        // when the session was minted.
        "admin": sessions.is_admin(app.store.as_ref(), &unlocked),
    }))
}

/// The live account id behind a session, or the error that ends the call.
fn account_id_of(
    app: &AppState,
    session: &Session,
) -> Result<(IdentityLinks, uuid::Uuid), AppError> {
    let links = IdentityLinks::new(app.store.clone());
    let user_id = links
        .account_id_of(&session.address)
        .map_err(|_| AppError::new("Session.AccountMissing", "this mailbox no longer exists"))?;
    Ok((links, user_id))
}

/// `session.identities` — the sign-ins linked to the authenticated mailbox.
async fn list_identities(app: &AppState, session: &Session) -> Result<Value, AppError> {
    let (links, user_id) = account_id_of(app, session)?;
    let listed = links
        .list_for_user(user_id)
        .await
        .map_err(|e| AppError::new("Admin.StoreFailed", e.to_string()))?;
    let identities: Vec<Value> = listed
        .iter()
        .map(|link| {
            json!({
                "provider": link.identity.provider,
                "subject": link.identity.subject,
                "created_at": link.created_at,
                "last_login_at": link.last_login_at,
            })
        })
        .collect();
    Ok(json!({ "identities": identities }))
}

/// `session.unlinkIdentity {provider}` — remove one linked sign-in from
/// the authenticated mailbox. Always allowed for the owner once the
/// mailbox is unlocked (the dispatcher saw to that): an own-domain
/// account keeps its password whatever is linked.
async fn unlink_identity(
    app: &AppState,
    session: &Session,
    params: &Value,
) -> Result<Value, AppError> {
    let provider = required(params, "provider")?;
    let (links, user_id) = account_id_of(app, session)?;
    let store_failed = |e: anyhow::Error| AppError::new("Admin.StoreFailed", e.to_string());
    let listed = links.list_for_user(user_id).await.map_err(store_failed)?;
    let Some(link) = listed
        .iter()
        .find(|link| link.identity.provider == provider)
    else {
        return Err(AppError::new(
            "Session.IdentityUnknown",
            "that provider is not linked to this mailbox",
        ));
    };
    let removed = links
        .unlink(&link.identity, user_id)
        .await
        .map_err(store_failed)?;
    Ok(json!({ "ok": true, "removed": removed }))
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
        Err(
            LoginError::UnknownAccount | LoginError::InvalidCredentials | LoginError::NotLocked,
        ) => Err(AppError::new(
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
    session_for(sessions, ctx, token_of(params))
}

/// The session of `token` — of the connection's when `None` — pinned on
/// the connection from here on. For the handlers that are handed their
/// params field by field and so have no params object to resolve against.
fn session_for(
    sessions: &SessionStore,
    ctx: &mut WsContext,
    token: Option<String>,
) -> Result<Session, AppError> {
    let token = token
        .or_else(|| ctx.token.clone())
        .ok_or_else(|| AppError::new("Session.Required", "login first"))?;
    let session = sessions
        .resolve(&token)
        .map_err(|_| AppError::new("Session.Required", "session expired or unknown"))?;
    ctx.token = Some(token);
    Ok(session)
}

/// The gate of the methods that CHANGE an account's linked sign-ins.
///
/// MUT:locked-no-link-changes — the mailbox password is the account's
/// second factor for its sign-ins exactly as it is for every privileged
/// surface: while a provider-minted session still owes it, nothing can be
/// linked to the mailbox and nothing unlinked from it. Refused by name,
/// before the store is touched, with the words the mail and admin
/// refusals use.
fn require_mailbox_unlocked(session: Session) -> Result<Session, AppError> {
    if session.mailbox_locked() {
        return Err(mailbox_locked());
    }
    Ok(session)
}

fn require_admin(
    app: &AppState,
    sessions: &SessionStore,
    ctx: &mut WsContext,
    params: &Value,
) -> Result<(), AppError> {
    let session = session_of(sessions, ctx, params)?;
    // MUT:locked-no-admin — the mailbox password is the account's second
    // factor for every privileged surface, not only for the mailbox: a
    // provider-minted session that still owes it administers nothing, even
    // when its account is an administrator. Refused by name, before the
    // grant is consulted, with the same words the mail methods use.
    if session.mailbox_locked() {
        return Err(mailbox_locked());
    }
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

// ── mail methods ─────────────────────────────────────────────────────────

/// The mailbox reader every mail method goes through.
///
/// The webmail used to be an IMAP client of Dovecot; the engine writes the
/// maildirs itself now, so the read path is a walk over `mail_root` and there
/// is no connection, no login and no session password involved. The reader is
/// a root path and nothing else — its append sequence is the process's, not
/// the instance's — so building one per request costs nothing.
fn reader_of(app: &AppState) -> ayane_smtpd::MaildirReader {
    ayane_smtpd::MaildirReader::new(app.config.mail.mail_root.clone())
}

/// Run a blocking maildir operation off the reactor.
///
/// The reader is ordinary file I/O — `readdir`, `open`, `read`, `rename` —
/// and a handler that runs it inline would block one of the reactor's worker
/// threads for as long as the mount takes. On a healthy local disk that is
/// microseconds; on a stalled NFS mount it is unbounded, and a handful of
/// such requests is enough to make the whole control plane unresponsive.
/// `spawn_blocking` moves each one to the blocking pool, which is what it is
/// for.
///
/// It bounds *what a request occupies*, not *how long it waits*: a blocking
/// task cannot be cancelled, so a genuinely hung mount still pins its pool
/// thread until the kernel gives up. That is the reactor's protection, not an
/// I/O timeout — a mount that never answers needs the mount fixed, and the
/// pool grows rather than blocking the whole runtime while it waits.
async fn blocking<T, F>(work: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(joined) => Err(AppError::new(
            "Mail.StorageFailed",
            format!("the maildir task did not finish: {joined}"),
        )),
    }
}

/// A [`ayane_smtpd::ReaderError`] as the RPC error the webui sees.
fn reader_error(error: ayane_smtpd::ReaderError) -> AppError {
    let path = match &error {
        ayane_smtpd::ReaderError::Missing { .. } => "Mail.NotFound",
        ayane_smtpd::ReaderError::BadFolder(_)
        | ayane_smtpd::ReaderError::BadMessageId(_)
        | ayane_smtpd::ReaderError::BadAddress(_) => "Mail.MalformedParams",
        ayane_smtpd::ReaderError::Unparsable(_) => "Mail.Unparsable",
        ayane_smtpd::ReaderError::NameTaken(_, _) => "Mail.Conflict",
        ayane_smtpd::ReaderError::Io { .. } => "Mail.StorageFailed",
    };
    AppError::new(path, error.to_string())
}

async fn mail_list(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let mailbox = mailbox_of(&params, ayane_smtpd::INBOX_FOLDER);
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 200) as usize;
    let identity = read_identity(&app, &session, identity_of(&params))?;
    let reader = reader_of(&app);
    let folder = mailbox.clone();
    let listing =
        blocking(move || reader.list(&identity, &folder, limit).map_err(reader_error)).await?;
    Ok(json!({
        "mailbox": mailbox,
        "total": listing.total,
        "unread": listing.unread,
        "messages": listing.messages,
    }))
}

async fn mail_read(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let id = message_id_of(&params)?;
    let mailbox = mailbox_of(&params, ayane_smtpd::INBOX_FOLDER);
    let mark_seen = params.get("markSeen").and_then(Value::as_bool) != Some(false);
    let identity = read_identity(&app, &session, identity_of(&params))?;
    let reader = reader_of(&app);
    // Opening and marking read are one blocking unit: the second is a rename
    // of the file the first just found, so separating them would let another
    // process move it in between and turn "mark read" into a `NotFound`.
    let folder = mailbox.clone();
    let (id, flags, message) = blocking(move || {
        let opened = reader.read(&identity, &folder, &id).map_err(reader_error)?;
        // Marking read is part of what `mail.read` was asked to do, so a
        // failure to rename is reported rather than swallowed: answering with
        // the old name and `seen: false` would tell the reader their message
        // was marked when the file still says otherwise.
        if mark_seen && !opened.flags.seen {
            let renamed = reader
                .set_flags(
                    &identity,
                    &folder,
                    &opened.id,
                    ayane_smtpd::FlagChange {
                        seen: Some(true),
                        ..ayane_smtpd::FlagChange::default()
                    },
                )
                .map_err(reader_error)?;
            Ok((renamed.to, renamed.flags, opened.message))
        } else {
            Ok((opened.id, opened.flags, opened.message))
        }
    })
    .await?;
    let links = ayane_mail::phishing::analyze(message.text.as_deref(), message.html.as_deref());
    Ok(json!({
        "uid": id,
        "mailbox": mailbox,
        "flags": {
            "seen": flags.seen,
            "flagged": flags.flagged,
        },
        "message": message,
        "links": links,
    }))
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
    // The envelope sender is the ACCOUNT, always — never a variant of it.
    // The header carries whatever the user chose; `MAIL FROM` carries the
    // address that exists, so SPF, DKIM alignment and bounces stay with the
    // mailbox (lettre would otherwise derive the envelope from the From
    // header). A shared mailbox's From is the only case where the two differ
    // in *identity* rather than in spelling, and there the account is still
    // the party that authenticated.
    let envelope_from = session.address.clone();
    let attachments = attachments_of(&params)?;

    let message = if attachments.is_empty()
        && params.get("format").and_then(Value::as_str) != Some("markdown")
    {
        ayane_mail::compose::build_plain_message_as(
            &from_address,
            &from_name,
            &envelope_from,
            &to,
            &subject,
            &body,
        )
        .map_err(|e| AppError::new("Mail.ComposerRejected", e.to_string()))?
    } else {
        let markdown = params.get("format").and_then(Value::as_str) == Some("markdown");
        ayane_mail::compose::build_composed_message_as(
            &from_address,
            &from_name,
            &envelope_from,
            &to,
            &subject,
            &body,
            &attachments,
            markdown,
        )
        .map_err(|e| AppError::new("Mail.ComposerRejected", e.to_string()))?
    };
    // The sender rules run before anything is written, exactly where the
    // submission listener runs them for an SMTP client: a deny-listed sender
    // is refused at the door, not queued and then silently discarded by the
    // router. A webmail send must not be a hole in the rules the operator
    // wrote. Only the deny list is consulted — that is the rule that judges a
    // *sender*, which is what this process can decide on its own; whether the
    // recipient is hosted belongs to the delivery layer, which knows what
    // leaves over MX.
    // Both addresses are judged. `envelope_from` is what SPF, DKIM alignment
    // and bounces ride on; `from_address` is what the recipient *reads*, and
    // it can be a shared mailbox the sender is a member of. A rule written
    // against the address the operator denied has to stop that address
    // appearing on the wire — judging only the envelope would leave the
    // header free to say what the rule forbids.
    let denied = |address: &ayane_proto::Address| {
        stored
            .desired
            .policy
            .denylist
            .iter()
            .any(|rule| rule.matches(address))
    };
    if denied(&envelope_from) || denied(&from_address) {
        return Err(AppError::new(
            "Mail.Rejected",
            "the policy refuses this sender",
        ));
    }
    let raw = ayane_mail::compose::render(&message);
    // The message enters the engine's own queue the way a message from any
    // other client does — one `Received:` field, one envelope — and the
    // delivery consumer decides what is local and what leaves over MX. The
    // webmail is a submission client of this process, not of a Postfix
    // listener somebody has to keep running beside it.
    // Queuing and the two maildir writes are one blocking unit: they are
    // filesystem work (a spool `fsync` and two renames), and the reactor must
    // not wait on them.
    let draft = params
        .get("draftUid")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned);
    let sent_identity = from_address.clone();
    let recipient = to.clone();
    let (session, app2) = (session.clone(), app.clone());
    blocking(move || {
        submit_locally(&app2, &session, &from_address, &recipient, &raw)?;
        let reader = reader_of(&app2);
        // The Sent copy belongs in the mailbox the message was sent *as* —
        // a shared mailbox the sender is a member of files its own mail.
        // Best effort: a failure must not fail a send that is already
        // queued, so the answer stays `queued: true` and the failure is
        // logged, because "sent with no copy in Sent" is a thing an operator
        // has to be able to find.
        if let Err(error) = reader.append(
            &sent_identity,
            ayane_smtpd::SENT_FOLDER,
            &raw,
            ayane_smtpd::Flags {
                seen: true,
                ..ayane_smtpd::Flags::default()
            },
        ) {
            tracing::warn!(%error, "the Sent copy could not be written");
        }
        // Sending a DRAFT retires the draft copy (best effort, like the Sent
        // copy — a failed cleanup must not fail an already-queued send). The
        // draft lives in whatever maildir `mail.saveDraft` wrote it to: the
        // identity the composer was on, not always the session's own.
        if let Some(draft) = draft {
            match read_identity(&app2, &session, identity_of(&params)) {
                Ok(identity) => {
                    if let Err(error) = reader.purge(&identity, ayane_smtpd::DRAFTS, &draft) {
                        tracing::warn!(%error, draft, "the sent draft could not be retired");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error.path, draft, "the draft's identity could not be resolved");
                }
            }
        }
        Ok(())
    })
    .await?;
    Ok(json!({ "queued": true, "to": to.as_str() }))
}

/// Stage a composed message in the engine's spool as one the submission
/// surface authenticated.
///
/// The envelope is the shape the delivery consumer
/// ([`crate::engine`]'s delivery loop) expects: a reverse-path of the account,
/// the recipients the headers name, and one trace field recording that this
/// process composed the message for an authenticated session. Nothing is
/// written into a maildir here — the consumer is the only writer, so a send
/// and a delivery cannot disagree about a mailbox's layout.
fn submit_locally(
    app: &AppState,
    session: &Session,
    from: &ayane_proto::Address,
    to: &ayane_proto::Address,
    raw: &[u8],
) -> Result<(), AppError> {
    let mail = &app.config.mail;
    let spool = ayane_smtpd::Spool::open(&mail.spool_root)
        .map_err(|e| AppError::new("Mail.StorageFailed", e.to_string()))?;
    let id = spool.next_id();
    // The engine's own clock, not a calendar library: `received_at` is RFC
    // 3339 and the `Received:` below is RFC 5322, both rendered from one
    // reading of the same clock.
    let now_epoch = ayane_smtpd::server::received_now_epoch();
    let received_at = ayane_smtpd::server::format_rfc3339(now_epoch);
    let mut envelope = ayane_smtpd::Envelope::placeholder(&id, &mail.hostname);
    envelope.received_at.clone_from(&received_at);
    envelope.mail_from = from.as_str().to_owned();
    envelope.mail_from_wire = format!("<{}>", from.as_str());
    // No `helo` and no `remote_ip`: this message did not arrive over a
    // connection, so there is no peer name to record and no host to name.
    // The placeholder seeded `helo` with our own name and would record
    // `127.0.0.1` as a peer that never connected; both are cleared here.
    envelope.helo = String::new();
    envelope.remote_ip = String::new();
    envelope.authenticated = Some(session.address.as_str().to_owned());
    envelope.recipients = vec![to.as_str().to_owned()];
    // RFC 5321 §4.4 allows a trace field for a submission; the `with`
    // protocol token is `ESMTPA` only when SMTP authenticated, which is not
    // what happened here. `ayane` with the session's own address says what
    // did: a local submission from an authenticated session.
    envelope.received = format!(
        "from {} by {} (ayane submission) id {}; {}",
        session.address.as_str(),
        mail.hostname,
        id,
        received_at
    );
    // This message was not verified: it was composed here, by a session this
    // process authenticated, and no SPF/DKIM/DMARC check applies to a
    // locally-originated message whose sender is the account itself.
    // Claiming `spf=pass … dkim=pass … dmarc=pass` here would be a forged
    // verdict — a statement about checks nobody ran — so the summary says
    // exactly what happened.
    envelope.auth_summary = format!(
        "authenticated=submission identity={} (locally composed; no inbound verification ran)",
        session.address.as_str()
    );
    let mut staged = spool
        .stage(&id, envelope)
        .map_err(|e| AppError::new("Mail.StorageFailed", e.to_string()))?;
    staged
        .write(raw)
        .map_err(|e| AppError::new("Mail.StorageFailed", e.to_string()))?;
    let received = format!("Received: {}\r\n", staged.envelope().received);
    staged
        .commit_with_prepend(received.as_bytes())
        .map_err(|e| AppError::new("Mail.StorageFailed", e.to_string()))?;
    Ok(())
}

/// The composer's attachments, base64-decoded, with the size caps one
/// request may carry (the engine queue enforces the real limits).
fn attachments_of(
    params: &Value,
) -> Result<Vec<ayane_mail::compose::OutgoingAttachment>, AppError> {
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
    Ok(attachments)
}

/// Save the composer's current state as a DRAFT: build the message with
/// draft semantics (the recipient may be half-typed) and append it to the
/// Drafts folder, which is autocreated like every folder the webmail touches.
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
    let (identity, display) = read_identity_with_display(&app, &session, identity_of(&params))?;
    let message =
        ayane_mail::compose::build_draft_message(&identity, &display, &to, &subject, &body)
            .map_err(|e| AppError::new("Mail.ComposerRejected", e.to_string()))?;
    let reader = reader_of(&app);
    // Saving a draft the composer was opened on replaces it: the old copy is
    // removed and the new one appended. Without this, "save" on a continued
    // draft leaves two, and the composer's own `draftUid` still names the
    // first — so sending would retire the stale one and leave the newer copy
    // behind. The removal runs first and its failure is not fatal (an append
    // that then succeeds is still the user's draft saved; a duplicate is the
    // failure mode worth a log line, not a lost save).
    let previous = params
        .get("draftUid")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned);
    let raw = ayane_mail::compose::render(&message);
    let id = blocking(move || {
        if let Some(previous) = previous {
            if let Err(error) = reader.purge(&identity, ayane_smtpd::DRAFTS, &previous) {
                tracing::warn!(%error, draft = previous, "the previous draft could not be retired");
            }
        }
        // A draft is unseen until the user opens it (Dovecot's rule for a
        // flagless append), and it carries no `S`.
        reader
            .append(
                &identity,
                ayane_smtpd::DRAFTS,
                &raw,
                ayane_smtpd::Flags::default(),
            )
            .map_err(reader_error)
    })
    .await?;
    Ok(json!({ "saved": true, "uid": id }))
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
    let identity = read_identity(&app, &session, identity_of(&params))?;
    let reader = reader_of(&app);
    let listing = blocking(move || {
        reader
            .list_flagged(&identity, &ayane_smtpd::STARRED_FOLDERS, limit)
            .map_err(reader_error)
    })
    .await?;
    // Same keys `mail.list` answers with, so the webui's one row shape fits
    // both: `unread` is the starred rows nobody has opened yet, which is what
    // the badge would show if the view had one.
    let unread =
        u32::try_from(listing.messages.iter().filter(|row| !row.seen).count()).unwrap_or(u32::MAX);
    Ok(json!({
        "mailbox": "Starred",
        "total": listing.total,
        "unread": unread,
        "messages": listing.messages,
    }))
}

/// Toggle the `F` (star) flag on one message.
async fn mail_star(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let id = message_id_of(&params)?;
    let mailbox = mailbox_of(&params, ayane_smtpd::INBOX_FOLDER);
    let starred = params.get("starred").and_then(Value::as_bool) != Some(false);
    let identity = read_identity(&app, &session, identity_of(&params))?;
    let reader = reader_of(&app);
    let renamed = blocking(move || {
        reader
            .set_flags(
                &identity,
                &mailbox,
                &id,
                ayane_smtpd::FlagChange {
                    flagged: Some(starred),
                    ..ayane_smtpd::FlagChange::default()
                },
            )
            .map_err(reader_error)
    })
    .await?;
    // Starring renames the file (the `F` goes into its suffix), so the answer
    // carries the name it has afterwards: the caller's next action on this
    // row has to name the file that exists. Setting the flag that is already
    // set renames nothing, and then the two are the same string — which is
    // also a correct answer, so no assertion compares them.
    Ok(json!({ "ok": true, "starred": starred, "uid": renamed.to }))
}

/// Delete one message: move it to the auto-created Trash folder. Refused for
/// messages already in Trash — permanent deletion there is `mail.purge`
/// behind a confirm.
async fn mail_trash(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let id = message_id_of(&params)?;
    let mailbox = mailbox_of(&params, ayane_smtpd::INBOX_FOLDER);
    if mailbox.eq_ignore_ascii_case(ayane_smtpd::TRASH_FOLDER) {
        return Err(AppError::new(
            "Mail.MalformedParams",
            "already in Trash: use mail.purge",
        ));
    }
    let identity = read_identity(&app, &session, identity_of(&params))?;
    let reader = reader_of(&app);
    let moved = blocking(move || {
        reader
            .move_to(&identity, &mailbox, &id, ayane_smtpd::TRASH_FOLDER)
            .map_err(reader_error)
    })
    .await?;
    Ok(json!({ "ok": true, "uid": moved.to, "mailbox": ayane_smtpd::TRASH_FOLDER }))
}

/// Permanently delete one message from the folder the caller names.
///
/// `mail.trash` is the two-step delete's first half and refuses to run on a
/// message already in Trash; this is the second half, and it deletes from
/// whatever folder it is given. The webui only ever calls it from the Trash
/// view (behind a confirm), but the handler does not assume that: a caller
/// that names INBOX gets an INBOX message destroyed, which is what it asked
/// for. The folder is required (never defaulted) so that a call cannot reach
/// a folder it did not name.
async fn mail_purge(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let id = message_id_of(&params)?;
    // The folder is required, not defaulted: a `mail.purge {uid}` with the
    // mailbox left out used to unlink whatever that id named, in whichever
    // folder it named — a permanent delete one forgotten field away from the
    // INBOX. An empty value is the webui's "not resolved yet", so it is
    // refused rather than filled in.
    let mailbox = params
        .get("mailbox")
        .and_then(Value::as_str)
        .filter(|mailbox| !mailbox.trim().is_empty())
        .ok_or_else(|| AppError::new("Mail.MalformedParams", "mailbox is required"))?
        .to_owned();
    let identity = read_identity(&app, &session, identity_of(&params))?;
    let reader = reader_of(&app);
    blocking(move || reader.purge(&identity, &mailbox, &id).map_err(reader_error)).await?;
    Ok(json!({ "ok": true }))
}

/// The `uid` param: a message id, which in a maildir is the file name.
///
/// The field keeps its old name because the webui sends it; its value used to
/// be an IMAP UID number and is now the file name (`<unique>:2,<flags>`).
fn message_id_of(params: &Value) -> Result<String, AppError> {
    params
        .get("uid")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned)
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
    // The variant switches ride along so the composer can tell a user their
    // own address also works with dots or a `+tag`. They list no extra
    // identities: a variant is something the user constructs, and only the
    // folders it reaches are real.
    let variants = &stored.desired.policy.variants;
    Ok(json!({
        "identities": identities,
        "variants": {
            "outbound_dots": variants.outbound_dots,
            "outbound_plus": variants.outbound_plus,
        },
    }))
}

/// Resolve the mailbox identity a mail operation runs against: the session's
/// own address by default, or a shared mailbox the account is a member of
/// (公共信箱).
///
/// Membership in `state.shared` **is** the grant. The reader opens the
/// shared address's maildir directly, so there is no second credential to
/// present: the machine password the IMAP era minted for this lookup had no
/// other consumer and is gone with it. [`read_identity`] is the same answer
/// for the callers that do not need the display name.
fn read_identity(
    app: &AppState,
    session: &Session,
    requested: Option<&str>,
) -> Result<ayane_proto::Address, AppError> {
    resolve_read_identity(app, session, requested).map(|(address, _display)| address)
}

/// [`read_identity`] with the display name the composer shows in a draft's
/// `From` field.
fn read_identity_with_display(
    app: &AppState,
    session: &Session,
    requested: Option<&str>,
) -> Result<(ayane_proto::Address, String), AppError> {
    resolve_read_identity(app, session, requested)
}

fn resolve_read_identity(
    app: &AppState,
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
    let display = parsed.local().to_owned();
    Ok((parsed, display))
}

/// Validate a requested send identity: the session's own address, a shared
/// mailbox it belongs to, or — when the administrator enabled the matching
/// switch — a Gmail-style variant of its own address (dots folded and/or a
/// `+tag` stripped back to the primary address).
///
/// The variant is only ever a *grant*: the From header keeps the address the
/// user typed (the recipient sees the tag they chose), while the caller keeps
/// the envelope sender on the session's own address — see `mail_send`. `own`
/// itself is never normalized, only the request, so with every switch off the
/// answer is exactly the pre-feature one.
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
    if variant_of(&stored.desired.policy.variants, &parsed, &own) {
        return Ok((parsed, session.display_name.clone()));
    }
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

/// Whether `requested` is an address-variant of `own` that the policy allows.
///
/// A variant is judged by folding it down to the form the switches name —
/// dots removed when `outbound_dots` is on, the `+tag` cut off when
/// `outbound_plus` is on — and comparing that with `own`. The fold is done in
/// one order for both switches (tag first, then dots), the same order the
/// inbound map folds in, so `a.b+x@d`, `a.b@d` and `a@d` all agree about what
/// the base mailbox is. A combined variant such as `a.b+tag@d` therefore
/// needs *both* switches: any switch that is off leaves a piece of the fold
/// in place, and the comparison fails.
fn variant_of(
    variants: &ayane_proto::AddressVariants,
    requested: &ayane_proto::Address,
    own: &ayane_proto::Address,
) -> bool {
    if !variants.any_outbound() {
        return false;
    }
    let mut folded = requested.clone();
    if variants.outbound_plus {
        folded = folded.strip_plus();
    }
    if variants.outbound_dots {
        folded = folded.fold_dots();
    }
    folded == *own
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

/// Edit the snapshot the way a slice handler must: one locked
/// read-modify-write ([`ayane_store::StateStore::update`]).
///
/// `edit` runs with the store's lock held, on the LATEST saved snapshot:
/// a link committed, a grant flipped or a whole-state replacement landed a
/// moment earlier is there to be edited, and nothing can slip in between
/// the read and the write. (An unlocked `load` → edit → `save` writes back
/// everything it read, which is how a change made meanwhile used to
/// vanish.) A refusal from `edit` leaves the stored snapshot untouched
/// and is answered as returned.
fn update_state(
    app: &AppState,
    edit: &mut dyn FnMut(&mut StoredState) -> Result<Value, AppError>,
) -> Result<Value, AppError> {
    let store_failed =
        |e: ayane_store::StoreError| AppError::new("Admin.StoreFailed", e.to_string());
    let mut answer: Option<Result<Value, AppError>> = None;
    // The edit's own refusal rides the store's `Rejected` out of the
    // closure, so `update` writes nothing and keeps the lock to the end.
    let written = app.store.update(&mut |state| match edit(state) {
        Ok(value) => {
            answer = Some(Ok(value));
            Ok(())
        }
        Err(refusal) => {
            answer = Some(Err(refusal));
            Err(ayane_store::StoreError::Rejected(
                "refused by the handler; nothing written".to_owned(),
            ))
        }
    });
    match answer {
        // The edit refused: nothing was written, and its reason stands.
        Some(Err(refusal)) => Err(refusal),
        Some(Ok(value)) => written.map(|()| value).map_err(store_failed),
        // The edit never ran: the snapshot could not be read.
        None => Err(written.err().map_or_else(
            || AppError::new("Admin.StoreFailed", "the edit did not run"),
            store_failed,
        )),
    }
}

/// Flip one account's administrator grant WITHOUT touching its password
/// (the whole-state PUT would demand every password; a role change is not
/// a credential change).
fn set_account_admin(app: &AppState, params: &Value) -> Result<Value, AppError> {
    let address = required(params, "address")?;
    let address = ayane_proto::Address::parse(&address)
        .map_err(|e| AppError::new("Admin.MalformedState", e.to_string()))?;
    let admin = params.get("admin").and_then(Value::as_bool) == Some(true);
    // MUT:locked-admin-write — the flip reads and writes under the store's
    // lock; an unlocked load → save here wrote back a snapshot from before
    // a link committed meanwhile and dropped it.
    update_state(app, &mut |stored| {
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
        Ok(json!({ "saved": true, "address": address.as_str(), "admin": admin }))
    })
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

/// Mail traffic of the recent window (default 72h).
///
/// The numbers come from the mail service's own counters
/// ([`ayane_smtpd::metrics`]) through [`crate::driver::EngineDriver::traffic_snapshot`],
/// not from a parsed engine log — there is no longer an engine log to parse,
/// and the counters cannot drift from the events they count.
///
/// # The shape, and why it is additive
///
/// The page drew two tables, `inbound` (one row per peer, with `connects`) and
/// `outbound` (one row per relay, with `domains`, `sent`, `deferred`,
/// `bounced`), and this reply keeps both **field names and semantics** so a
/// webui build from before the change renders it unchanged:
///
/// - `inbound[].peer` / `inbound[].connects` are the same two fields, now
///   counted from accepted connections instead of parsed `connect from` lines;
/// - `outbound[].sent` / `deferred` / `bounced` are counted per *destination
///   domain* rather than per relay host, and `outbound[].domains` carries the
///   single domain each row is about — the one shape difference, and the reason
///   it is spelled out here: the outbound transport resolves an MX per attempt
///   and does not keep that host anywhere a counter could read it, while the
///   domain is in the request it was asked about.
///
/// Everything else (`messages`, `recipients`, `refused`, `window_seconds`,
/// `totals`) is additive: a panel that does not know the fields ignores them.
async fn net_traffic(app: &AppState, params: Value) -> Result<Value, AppError> {
    let since = params
        .get("since")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("72h")
        .to_owned();
    let snapshot = app
        .driver
        .traffic_snapshot(&since)
        .map_err(|e| AppError::new("Admin.ApplyFailed", e))?;
    Ok(crate::net::traffic_reply(&snapshot))
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
    let variants = &stored.desired.policy.variants;
    Ok(json!({
        "allowlist": rules(&stored.desired.policy.allowlist),
        "denylist": rules(&stored.desired.policy.denylist),
        "variants": {
            "inbound_dots": variants.inbound_dots,
            "inbound_plus": variants.inbound_plus,
            "outbound_dots": variants.outbound_dots,
            "outbound_plus": variants.outbound_plus,
        },
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
    // The variant switches are a write of their own: absent keeps whatever
    // the locked read sees, so a client that only edits the lists never
    // resets them — and never writes back a value read before another writer
    // committed.
    let variants = params
        .get("variants")
        .map(|value| {
            serde_json::from_value::<ayane_proto::AddressVariants>(value.clone()).map_err(|e| {
                AppError::new("Admin.MalformedState", format!("invalid variants: {e}"))
            })
        })
        .transpose()?;
    // MUT:locked-admin-write — one locked read-modify-write, like every
    // other slice edit (see `set_account_admin`).
    update_state(app, &mut |stored| {
        stored.desired.policy.allowlist = allowlist.clone();
        stored.desired.policy.denylist = denylist.clone();
        if let Some(variants) = &variants {
            stored.desired.policy.variants = *variants;
        }
        stored
            .desired
            .validate()
            .map_err(|e| AppError::new("Admin.StateRejected", e.to_string()))?;
        Ok(json!({ "saved": true, "note": "apply to reload the engine" }))
    })
}

// ── domain DKIM selection ─────────────────────────────────────────────────

/// `admin.domain.dkim.put {domain, selector}` — sets (or, with an empty
/// selector, clears) the DKIM selector one hosted domain signs with.
///
/// # Why this is an RPC and not a field of `admin.state.put`
///
/// `signers_from_env` signs a domain whose **state** carries a selector —
/// `<selector>._domainkey.<domain>` is the name the receiver queries — and the
/// key itself never travels with the state (it is read from the process
/// environment by sanitised domain name). Until this method existed nothing in
/// the service wrote that field: the panel's only route was its raw JSON
/// editor, which is how a live instance's selector came to be hand-edited.
///
/// The edit is one locked read-modify-write ([`update_state`]), so a concurrent
/// account edit is not lost to it, and the selector is put through the same
/// label law the whole snapshot is validated by, so a value that could never be
/// published as a DNS name is refused **here**, with the domain named — not on
/// the next `admin.apply`, where the message would have to be reversed to
/// find the field.
///
/// A selector reaches the signer set on the **next process start** (the keys
/// are loaded once at startup; see `engine::signers`), so the answer says so.
fn domain_dkim_put(app: &AppState, params: &Value) -> Result<Value, AppError> {
    let domain = required(params, "domain")?.trim().to_ascii_lowercase();
    // An empty selector is the "sign nothing for this domain" write: a domain
    // that used a selector and no longer does has to be able to say so, and the
    // alternative (delete the whole domain) drops its mailboxes with it.
    let selector = str_param(params, "selector")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let cleared = selector.is_empty();
    update_state(app, &mut |stored| {
        let Some(index) = stored
            .desired
            .domains
            .iter()
            .position(|candidate| candidate.name.eq_ignore_ascii_case(&domain))
        else {
            return Err(AppError::new(
                "Admin.UnknownDomain",
                format!("{domain} is not a hosted domain"),
            ));
        };
        stored.desired.domains[index].dkim = if cleared {
            None
        } else {
            Some(ayane_proto::DkimSigningConfig::selector_only(
                selector.clone(),
            ))
        };
        // The same validation every other write of a slice runs: the selector
        // law lives in `DesiredState::validate`, and duplicating it here would
        // be two spellings of one rule.
        stored
            .desired
            .validate()
            .map_err(|e| AppError::new("Admin.MalformedSelector", e.to_string()))?;
        Ok(json!({
            "saved": true,
            "domain": domain,
            "selector": if cleared { Value::Null } else { json!(selector) },
            "requires_restart": true,
            "note": "signers are loaded at start: restart the service, then apply",
        }))
    })
}

// ── audit (keyword + arona AI) ────────────────────────────────────────────

/// One flagged message from an audit pass.
#[derive(serde::Serialize)]
struct AuditHit {
    /// The message id (the maildir file name) of a hit.
    ///
    /// The audit table does not render it today; it is here so a reply that
    /// names a hit names the message it is about, which is what a follow-up
    /// action would need.
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<String>,
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
    if session.mailbox_locked() {
        return Err(mailbox_locked());
    }
    // The whole scan is one blocking unit: the listing, then one open per
    // row. Splitting it would cost a pool round-trip per message and still
    // leave the parse on the reactor.
    let reader = reader_of(app);
    let address = session.address.clone();
    let (mut hits, scanned): (Vec<AuditHit>, usize) = blocking(move || {
        let listing = reader
            .list(&address, ayane_smtpd::INBOX_FOLDER, limit)
            .map_err(reader_error)?;
        let mut hits: Vec<AuditHit> = Vec::new();
        for row in &listing.messages {
            // The audit is a reader: it never marks a message seen.
            let Ok(opened) = reader.read(&address, ayane_smtpd::INBOX_FOLDER, &row.id) else {
                continue;
            };
            let parsed = opened.message;
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
                    uid: Some(opened.id),
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
        // What the scan actually read: the page it asked for, not the
        // folder's size. "Scanned 20 messages" has to mean 20 messages were
        // opened and parsed — reporting the folder total would claim work
        // that did not happen, and `limit` is exactly the bound that says so.
        let opened = listing.messages.len();
        Ok((hits, opened))
    })
    .await?;

    // The AI leg: arona classifies each keyword hit (cheaper than scanning
    // everything, and the keyword leg already names the suspects).
    let ai = &stored.desired.audit.ai;
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

    Ok(json!({ "scanned": scanned, "flagged": hits.len(), "hits": hits }))
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
    // MUT:locked-admin-write — one locked read-modify-write, like every
    // other slice edit (see `set_account_admin`).
    update_state(app, &mut |stored| {
        stored.desired.mcp.tools = tools.clone();
        let minted = if rotate {
            let raw = uuid::Uuid::new_v4().simple().to_string()
                + &uuid::Uuid::new_v4().simple().to_string();
            stored.desired.mcp.token = raw.clone();
            Some(raw)
        } else {
            None
        };
        // The token is shown once, on the rotation reply — exactly like the
        // family's client-secret reveals.
        Ok(json!({ "saved": true, "token": minted }))
    })
}

/// Set or clear the `S` (seen) flag on one message.
///
/// `seen: false` reads as "mark unread" — the webui's menu sends the *new*
/// state and a missing key means "mark read", which is what the old
/// `Mail.MarkSeen` handler did and what every row menu still assumes.
async fn mail_mark_seen(app: AppState, session: Session, params: Value) -> Result<Value, AppError> {
    let id = message_id_of(&params)?;
    let mailbox = mailbox_of(&params, ayane_smtpd::INBOX_FOLDER);
    let unseen = params.get("seen").and_then(Value::as_bool) == Some(false);
    let identity = read_identity(&app, &session, identity_of(&params))?;
    let reader = reader_of(&app);
    let renamed = blocking(move || {
        reader
            .set_flags(
                &identity,
                &mailbox,
                &id,
                ayane_smtpd::FlagChange {
                    seen: Some(!unseen),
                    ..ayane_smtpd::FlagChange::default()
                },
            )
            .map_err(reader_error)
    })
    .await?;
    Ok(json!({ "ok": true, "seen": !unseen, "uid": renamed.to }))
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
    fn address(raw: &str) -> ayane_proto::Address {
        ayane_proto::Address::parse(raw).expect("fixture address")
    }

    fn variants(bits: u8) -> ayane_proto::AddressVariants {
        ayane_proto::AddressVariants {
            inbound_dots: bits & 1 != 0,
            inbound_plus: bits & 2 != 0,
            outbound_dots: bits & 4 != 0,
            outbound_plus: bits & 8 != 0,
        }
    }

    fn session_for(own: &str) -> Session {
        Session {
            address: address(own),
            display_name: "Tester".to_owned(),
            admin: false,
            password: Some("secret".to_owned()),
            needs_mailbox_password: false,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(60),
        }
    }

    /// A stored state with one account (`own`) and one shared mailbox it is a
    /// member of (`team@example.test`), so both the shared path and the
    /// variant path are reachable in the same fixture.
    fn store_for(own: &str, switches: ayane_proto::AddressVariants) -> ayane_store::StoredState {
        let account_id = uuid::Uuid::new_v4();
        let desired = ayane_proto::DesiredState {
            domains: vec![ayane_proto::MailDomain {
                name: "example.test".to_owned(),
                catch_all: None,
                enabled: true,
                dkim: None,
            }],
            accounts: vec![ayane_proto::Account {
                id: account_id,
                address: address(own),
                display_name: "Tester".to_owned(),
                quota_bytes: 0,
                admin: false,
            }],
            shared: vec![ayane_proto::SharedMailbox {
                id: uuid::Uuid::new_v4(),
                address: address("team@example.test"),
                members: vec![account_id],
            }],
            policy: ayane_proto::Policy {
                variants: switches,
                ..ayane_proto::Policy::default()
            },
            ..ayane_proto::DesiredState::default()
        };
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(own.to_owned(), "hash".to_owned());
        ayane_store::StoredState {
            desired,
            password_hashes: hashes,
            external_identities: Vec::new(),
        }
    }

    /// `resolve_send_identity` against `requested`, as the mail path calls it.
    fn send_as(
        own: &str,
        switches: ayane_proto::AddressVariants,
        requested: Option<&str>,
    ) -> Result<String, AppError> {
        let stored = store_for(own, switches);
        let session = session_for(own);
        resolve_send_identity(&stored, &session, requested)
            .map(|(from, _display)| from.as_str().to_owned())
    }

    #[test]
    fn every_outbound_switch_off_keeps_the_pre_feature_answers() {
        let own = "alice@example.test";
        // The account's own address, asked for or not, is itself.
        assert_eq!(send_as(own, variants(0), None).expect("own"), own);
        assert_eq!(send_as(own, variants(0), Some(own)).expect("own"), own);
        // The shared mailbox it belongs to still works.
        assert_eq!(
            send_as(own, variants(0), Some("team@example.test")).expect("shared"),
            "team@example.test"
        );
        // Every variant is refused, exactly as before the feature.
        for requested in [
            "al.ice@example.test",
            "alice+x@example.test",
            "al.ice+x@example.test",
        ] {
            let refused = send_as(own, variants(0), Some(requested));
            assert!(refused.is_err(), "`{requested}` must be refused");
            assert_eq!(
                refused.expect_err("refused").prose,
                "that shared mailbox does not belong to this account"
            );
        }
        // Inbound switches alone grant nothing outbound.
        assert!(send_as(own, variants(0b0011), Some("alice+x@example.test")).is_err());
    }

    #[test]
    fn outbound_dots_grants_dotted_forms_of_the_own_address() {
        let own = "alice@example.test";
        let on = variants(0b0100);
        for granted in [
            "al.ice@example.test",
            "a.l.i.c.e@example.test",
            "alice.@example.test",
            ".alice@example.test",
        ] {
            assert_eq!(send_as(own, on, Some(granted)).expect(granted), granted);
        }
        // A dot variant of somebody else, or of the shared mailbox, is not the
        // own address's variant and is still refused.
        assert!(send_as(own, on, Some("bob.smith@example.test")).is_err());
        assert!(send_as(own, on, Some("team.x@example.test")).is_err());
        // The plus tag is a different switch.
        assert!(send_as(own, on, Some("alice+x@example.test")).is_err());
        // Another domain never folds.
        assert!(send_as(own, on, Some("al.ice@elsewhere.test")).is_err());
    }

    #[test]
    fn outbound_plus_grants_tagged_forms_of_the_own_address() {
        let own = "alice@example.test";
        let on = variants(0b1000);
        for granted in [
            "alice+news@example.test",
            "alice+a+b@example.test",
            "alice+@example.test",
        ] {
            assert_eq!(send_as(own, on, Some(granted)).expect(granted), granted);
        }
        assert!(send_as(own, on, Some("bob+x@example.test")).is_err());
        assert!(send_as(own, on, Some("team+x@example.test")).is_err());
        // Dots are a different switch.
        assert!(send_as(own, on, Some("al.ice@example.test")).is_err());
    }

    #[test]
    fn a_combined_from_needs_both_outbound_switches() {
        let own = "alice@example.test";
        let combined = "al.ice+tag@example.test";
        // Both on: the tag strips and the dots fold onto the own address.
        assert_eq!(
            send_as(own, variants(0b1100), Some(combined)).expect("both on"),
            combined
        );
        // Either switch alone leaves a piece behind.
        assert!(send_as(own, variants(0b0100), Some(combined)).is_err());
        assert!(send_as(own, variants(0b1000), Some(combined)).is_err());
    }

    #[test]
    fn the_grant_never_widens_the_from_to_a_foreign_address() {
        let own = "alice@example.test";
        let switches = variants(0b1111);
        for foreign in [
            "bob@example.test",
            "alice@elsewhere.test",
            "alic@example.test",
            "alicee@example.test",
            "team@example.test.elsewhere",
        ] {
            assert!(
                send_as(own, switches, Some(foreign)).is_err(),
                "`{foreign}` must stay refused"
            );
        }
        // The shared membership path is unchanged by any switch.
        assert_eq!(
            send_as(own, switches, Some("team@example.test")).expect("shared"),
            "team@example.test"
        );
    }

    #[test]
    fn variant_of_folds_in_the_documented_order() {
        let own = address("alice@example.test");
        let all = variants(0b1111);
        assert!(variant_of(&all, &address("al.ice+tag@example.test"), &own));
        // Tag first, dots second: the order the inbound map folds in.
        assert_eq!(
            address("al.ice+tag@example.test").strip_plus().fold_dots(),
            own
        );
        // Outbound switches only: inbound ones grant nothing here.
        assert!(!variant_of(
            &variants(0b0011),
            &address("alice+x@example.test"),
            &own
        ));
        assert!(!variant_of(&variants(0), &own.clone(), &own));
    }

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

    // ── send identity: Gmail-style variants ─────────────────────────────
}
