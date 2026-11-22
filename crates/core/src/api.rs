//! The management API.
//!
//! v1 is deliberately small: read the desired state, replace it wholesale,
//! apply it to the engine. CRUD-per-object endpoints arrive with the webmail;
//! a replace-whole-state primitive keeps the smoke path and configuration as
//! code working first, and every write path runs the same validation.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use ayane_proto::{Account, Address, Alias, DesiredState, MailDomain, Policy, SharedMailbox};
use ayane_store::{password, StoredState};

use crate::apply::{self, ApplyReport};
use crate::state::AppState;

/// The request body of `PUT /api/v1/state`.
///
/// Mirrors [`DesiredState`] but carries account passwords (write-only) and
/// shared-mailbox members as addresses (resolved to account ids server-side).
#[derive(Debug, Clone, Deserialize)]
pub struct PutState {
    /// Hosted domains.
    pub domains: Vec<MailDomain>,
    /// Regular mailboxes.
    pub accounts: Vec<PutAccount>,
    /// Forwarding rules.
    pub aliases: Vec<Alias>,
    /// Shared mailboxes.
    pub shared: Vec<PutShared>,
    /// Recipient policy.
    #[serde(default)]
    pub policy: Policy,
    /// Message audit configuration; absent keeps the stored value (a state
    /// replacement must not silently unconfigure the audit surface).
    pub audit: Option<ayane_proto::AuditConfig>,
    /// MCP tool-surface configuration; absent keeps the stored value.
    pub mcp: Option<ayane_proto::McpConfig>,
}

/// One account as submitted: like [`Account`] plus the plaintext password.
#[derive(Debug, Clone, Deserialize)]
pub struct PutAccount {
    /// Primary address.
    pub address: Address,
    /// Display name.
    pub display_name: String,
    /// Quota in bytes; 0 = unlimited.
    #[serde(default)]
    pub quota_bytes: u64,
    /// Whether this account administers the service.
    #[serde(default)]
    pub admin: bool,
    /// Plaintext password (hashed and never stored in the clear).
    pub password: String,
}

/// One shared mailbox as submitted.
#[derive(Debug, Clone, Deserialize)]
pub struct PutShared {
    /// Shared address.
    pub address: Address,
    /// Member addresses (must all be existing accounts).
    pub members: Vec<Address>,
}

/// Acknowledgement of `PUT /api/v1/state`.
#[derive(Debug, Clone, Serialize)]
pub struct PutStateAck {
    /// Number of domains stored.
    pub domains: usize,
    /// Number of accounts stored.
    pub accounts: usize,
    /// Number of aliases stored.
    pub aliases: usize,
    /// Number of shared mailboxes stored.
    pub shared: usize,
}

/// A uniform error body.
#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    /// Human-readable reason.
    pub error: String,
    #[serde(skip)]
    status: StatusCode,
}

impl ApiError {
    /// The human-readable reason (for the ws error path).
    #[must_use]
    pub fn prose(&self) -> &str {
        &self.error
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self)).into_response()
    }
}

/// Mount the public and protected API routes onto an app router.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/state", get(get_state).put(put_state))
        .route("/apply", post(post_apply));
    Router::new()
        .route("/api/health", get(health))
        .fallback(crate::webui::serve)
        .nest(
            "/api/v1",
            protected.layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_admin,
            )),
        )
        .with_state(state)
}

/// The full application: the management REST face plus the ws/mcp
/// JSON-RPC surface.
pub fn full_router(surface: crate::transport::RpcSurface) -> Router {
    router(surface.app.clone()).merge(
        Router::new()
            .route("/api/ws", get(crate::transport::ws_handler))
            .route("/api/mcp", post(crate::transport::mcp_handler))
            .with_state(surface),
    )
}

async fn health() -> Json<crate::Health> {
    Json(crate::Health::default())
}

async fn get_state(State(app): State<AppState>) -> Result<Json<DesiredState>, ApiError> {
    let stored = load_stored(&app)?;
    Ok(Json(stored.desired))
}

async fn put_state(
    State(app): State<AppState>,
    Json(body): Json<PutState>,
) -> Result<Json<PutStateAck>, ApiError> {
    put_state_impl(&app, body).await.map(Json)
}

/// Shared by the REST handler and the ws `admin.state.put` method.
///
/// # Errors
///
/// Returns [`ApiError`] for every rejection the REST face would show.
pub async fn put_state_impl(app: &AppState, body: PutState) -> Result<PutStateAck, ApiError> {
    for account in &body.accounts {
        if account.password.len() < 8 {
            return Err(ApiError {
                error: format!(
                    "password for {} must be at least 8 characters",
                    account.address
                ),
                status: StatusCode::UNPROCESSABLE_ENTITY,
            });
        }
    }

    let ids_by_address: HashMap<String, Uuid> = body
        .accounts
        .iter()
        .map(|account| (account.address.to_string(), Uuid::new_v4()))
        .collect();

    // Absent audit/mcp slices keep their stored values — a state
    // replacement is not an unconfigure.
    let keep = match app.store.load() {
        Ok(stored) => stored.desired,
        Err(_) => DesiredState::default(),
    };
    let mut desired = DesiredState {
        domains: body.domains,
        accounts: Vec::with_capacity(body.accounts.len()),
        aliases: body.aliases,
        shared: Vec::with_capacity(body.shared.len()),
        policy: body.policy,
        audit: body.audit.unwrap_or(keep.audit),
        mcp: body.mcp.unwrap_or(keep.mcp),
    };
    let mut password_hashes = HashMap::with_capacity(body.accounts.len());

    for account in &body.accounts {
        let hash = password::hash_password(&account.password).map_err(|e| ApiError {
            error: format!("hash password for {}: {e}", account.address),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        })?;
        password_hashes.insert(account.address.to_string(), hash);
        desired.accounts.push(Account {
            id: ids_by_address[account.address.as_str()],
            address: account.address.clone(),
            display_name: account.display_name.clone(),
            quota_bytes: account.quota_bytes,
            admin: account.admin,
        });
    }

    for shared in &body.shared {
        let mut members = Vec::with_capacity(shared.members.len());
        for member in &shared.members {
            let id = ids_by_address
                .get(member.as_str())
                .ok_or_else(|| ApiError {
                    error: format!(
                        "shared mailbox {} references non-account member {member}",
                        shared.address
                    ),
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                })?;
            members.push(*id);
        }
        desired.shared.push(SharedMailbox {
            id: Uuid::new_v4(),
            address: shared.address.clone(),
            members,
        });
    }

    desired.validate().map_err(|e| ApiError {
        error: e.to_string(),
        status: StatusCode::UNPROCESSABLE_ENTITY,
    })?;

    let stored = StoredState {
        desired,
        password_hashes,
    };
    app.store.save(&stored).map_err(store_error)?;

    Ok(PutStateAck {
        domains: stored.desired.domains.len(),
        accounts: stored.desired.accounts.len(),
        aliases: stored.desired.aliases.len(),
        shared: stored.desired.shared.len(),
    })
}

async fn post_apply(State(app): State<AppState>) -> Result<Json<ApplyReport>, ApiError> {
    let stored = load_stored(&app)?;
    let report = apply::apply(&app.config.state_dir, &stored, app.driver.clone())
        .await
        .map_err(|e| ApiError {
            error: e.to_string(),
            status: StatusCode::CONFLICT,
        })?;
    Ok(Json(report))
}

fn load_stored(app: &AppState) -> Result<StoredState, ApiError> {
    app.store.load().map_err(store_error)
}

fn store_error(e: ayane_store::StoreError) -> ApiError {
    ApiError {
        error: e.to_string(),
        status: StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// `X-Admin-Token` (or `Authorization: Bearer`) gate for the management
/// surface. Compares in constant time so the token is not retrievable
/// through timing.
async fn require_admin(
    State(app): State<AppState>,
    headers: HeaderMap,
    _request: axum::extract::Request,
    next: Next,
) -> Response {
    let expected = match &app.config.admin_token {
        Some(token) => token,
        None => {
            return ApiError {
                error: "management API disabled: AYANE_ADMIN_TOKEN is not set".to_owned(),
                status: StatusCode::SERVICE_UNAVAILABLE,
            }
            .into_response()
        }
    };
    let provided = headers
        .get("x-admin-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(str::to_owned)
        })
        .unwrap_or_default();
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return ApiError {
            error: "invalid admin token".to_owned(),
            status: StatusCode::UNAUTHORIZED,
        }
        .into_response();
    }
    next.run(_request).await
}

/// Length-leaking-but-content-constant comparison (length is not a secret).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
