//! HTTP server exposing the node to clients (wallet, explorer, ...).
//!
//! Routes are registered but most return placeholders; business logic is not
//! implemented yet.

mod routes;

use actix_cors::Cors;
use actix_web::middleware::{Condition, Logger};
use actix_web::{web, App, HttpServer};

use crate::error::Result;
use crate::state::AppState;

/// Build and serve the HTTP API until the process exits.
pub async fn run(state: AppState) -> Result<()> {
    let addr = state.config.api.listen_addr;
    let enable_cors = state.config.api.enable_cors;
    let data = web::Data::new(state);

    tracing::info!(%addr, "HTTP API listening");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .wrap(Logger::default())
            .wrap(Condition::new(enable_cors, Cors::permissive()))
            .configure(routes::configure)
    })
    .bind(addr)?
    .run()
    .await?;

    Ok(())
}
