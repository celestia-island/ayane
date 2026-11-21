//! Process entry point for the ayane control plane.

use ayane::config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&config.log_filter))
        .init();

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(
        listen = %config.listen,
        version = env!("CARGO_PKG_VERSION"),
        "ayane control plane starting"
    );
    axum::serve(listener, ayane::app()).await?;
    Ok(())
}
