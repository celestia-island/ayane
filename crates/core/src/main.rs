//! Process entry point for the ayane control plane — and, when the mail
//! section is enabled, for the mail service it drives.
//!
//! `ayane serve` (the default, and the only mode) starts the HTTP surface and,
//! if [`Config::mail`](ayane::config::Config::mail) says so, the SMTP
//! listeners, the delivery consumer and the outbound transport **in this
//! process**. That is the shape the deployment runs: one unit, one state
//! directory, one set of counters, with the control plane's reload reaching
//! the listener through an `ArcSwap` instead of through a `docker compose exec`.
//!
//! With the mail section disabled the process is what it always was: the store,
//! the auth state and the RPC surface. Nothing binds a port, opens a spool or
//! starts a task, so an installation that has not enabled it sees no change.

use std::sync::Arc;

use kirino::auth::passport::oauth::HttpFetcher;

use ayane::auth::{AuthState, NoFetcher, ProviderCatalog, ReqwestFetcher};
use ayane::config::Config;
use ayane::driver::{EngineDriver, NativeDriver, RecordingDriver};
use ayane::state::AppState;
use ayane::transport::RpcSurface;
use ayane_store::RedbStateStore;

/// What `--version` prints, and the one string a deployment script needs to
/// answer "which build is on this host?" without starting a process that binds
/// a port or opens the store.
///
/// The **target triple and profile** are part of it on purpose: the cutover
/// this flag was added for failed because the binary on the host was built for
/// a newer glibc than the host has and did not contain the mail engine, and
/// neither fact was visible from the file name. A static musl build says
/// `x86_64-unknown-linux-musl` here.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CARGO_PKG_NAME"),
    " ",
    // From `build.rs`: the target this binary was **built for**, not the one
    // it happens to run on.
    env!("AYANE_BUILD_TARGET"),
    ")",
    "\nmail engine: linked (AYANE_MAIL_ENABLED=1 runs it in this process)",
);

/// Says whether this build is the one the deployment expects and exits.
///
/// Handled before anything is read from the environment or opened: `--version`
/// must answer on a host whose state directory does not exist yet, which is
/// exactly the host a cutover is being staged on.
fn print_version_if_asked() -> bool {
    let asked = std::env::args()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V");
    if asked {
        println!("{VERSION}");
    }
    asked
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if print_version_if_asked() {
        return Ok(());
    }
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&config.log_filter))
        .init();

    if let Some(parent) = config.store_path().parent() {
        std::fs::create_dir_all(parent)?;
    }
    let store = Arc::new(RedbStateStore::open(config.store_path())?);
    // Provider sign-in is read fail-closed: a provider variable that is
    // present but incomplete, or a policy that disagrees with itself,
    // refuses to start rather than quietly serve a password-only panel.
    let catalog = ProviderCatalog::from_env()?;
    let policy = catalog.validated_login_policy()?;
    let http: Arc<dyn HttpFetcher> = if catalog.has_providers() {
        Arc::new(ReqwestFetcher::new()?)
    } else {
        Arc::new(NoFetcher)
    };
    let auth = Arc::new(AuthState::new(catalog, http));

    // The engine seam. With the mail section enabled the driver is a handle on
    // the running service (reload = hot swap, traffic = counters); with it
    // disabled nothing in the process can answer a reload, and the recording
    // driver says so in the apply report instead of pretending.
    // A mail service that cannot start is reported, never fatal — unless the
    // deployment said `AYANE_MAIL_REQUIRE_START=1`, which is the only way this
    // `?` fires. The control plane below is bound and served either way: an
    // operator whose SMTP port is not up still needs `/api/health` to say so.
    let (driver, mail_health): (Arc<dyn EngineDriver>, Option<Arc<ayane::MailHealth>>) =
        if config.mail.enabled {
            let engine = ayane::engine::start(&config, store.clone()).await?;
            let listeners = config.mail.listeners.len();
            if let Some(degraded) = engine.degraded() {
                tracing::error!(
                    cause = degraded.cause,
                    reason = %degraded.reason,
                    "the mail service is degraded; the control plane serves without it"
                );
            } else {
                tracing::info!(
                    listeners,
                    spool = %config.mail.spool_root.display(),
                    mail_root = %config.mail.mail_root.display(),
                    outbound = config.mail.outbound,
                    dkim = config.mail.dkim_key_env.is_some(),
                    "mail engine started in this process"
                );
            }
            let health = ayane::MailHealth {
                serving: engine.degraded().is_none(),
                degraded: engine.degraded().cloned(),
                listeners,
            };
            (
                Arc::new(NativeDriver::new(engine.control().clone())),
                Some(Arc::new(health)),
            )
        } else {
            (
                Arc::new(RecordingDriver::new(config.compose_file.clone())),
                None,
            )
        };

    let state = AppState {
        store: store.clone(),
        driver,
        config: Arc::new(config.clone()),
        auth,
        mail_health: mail_health.clone(),
    };
    let sessions_path = config.state_dir.join("sessions.json");
    let surface = RpcSurface {
        app: state.clone(),
        sessions: Arc::new(ayane::session::SessionStore::with_persistence(
            sessions_path,
        )),
    };

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(
        listen = %config.listen,
        state_dir = %config.state_dir.display(),
        version = env!("CARGO_PKG_VERSION"),
        admin_api = if config.admin_token.is_some() { "enabled" } else { "disabled" },
        auth_mode = policy.mode.as_str(),
        mail = if config.mail.enabled { "native" } else { "disabled" },
        mail_serving = mail_health.as_ref().is_none_or(|mail| mail.serving),
        "ayane control plane starting"
    );
    axum::serve(listener, ayane::api::full_router(surface)).await?;
    Ok(())
}
