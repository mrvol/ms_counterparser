mod analyze;
mod challenge;
mod config;
mod dns;
mod ip_pools;
mod responses;
mod routes;
mod state;

use std::path::Path;
use std::sync::Arc;

use dns::{HickoryResolver, Resolver};
use state::AppState;

#[derive(Clone)]
pub struct Shared {
    pub state: Arc<AppState>,
    pub resolver: Arc<dyn Resolver>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config_path =
        std::env::var("COUNTERPARSER_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = config::Config::load(&config_path)?;
    let socket_path = config.server.socket_path.clone();

    let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system_conf()?);
    let state = Arc::new(AppState::new(config));
    let shared = Shared { state, resolver };

    let app = routes::router(shared);

    if Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    tracing::info!("listening on unix:{socket_path}");
    axum::serve(listener, app).await?;

    Ok(())
}
