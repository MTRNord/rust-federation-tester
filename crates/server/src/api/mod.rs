//! API module providing HTTP endpoints for the Federation Tester.
//!
//! This module is organized into submodules:
//! - `federation` - Federation tester endpoints (/api/federation/*)
//! - `alerts` - Alert management endpoints (/api/alerts/*)
//! - `alerts_v2` - v2 Alert management endpoints with OAuth2 (/api/v2/alerts/*)
//! - `auth` - Authentication extractors for OAuth2
//! - `health` - Health check endpoint (/healthz)
//! - `metrics` - Prometheus metrics endpoint (/metrics)
//! - `oauth2` - OAuth2 authentication endpoints (/oauth2/*)
//! - `openapi` - OpenAPI/Utoipa configuration

pub mod alerts;
pub mod alerts_v2;
pub mod auth;
pub mod debug;
pub mod federation;
pub mod health;
pub mod metrics;
pub mod openapi;

// Re-export oauth2 module from crate root
pub use crate::oauth2;

// Re-export for backward compatibility with existing code
pub use alerts::AlertAppState;
pub use federation::AppState;

// Re-export commonly used items
pub use alerts::ALERTS_TAG;
pub use federation::FEDERATION_TAG;
pub use health::MISC_TAG;

use crate::AppResources;
use axum_tracing_opentelemetry::middleware::{OtelAxumLayer, OtelInResponseLayer};
use hickory_resolver::name_server::ConnectionProvider;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_redoc::{Redoc, Servable};

// Backward compatible module aliases
pub mod alert_api {
    pub use super::alerts::*;
}

pub mod federation_tester_api {
    pub use super::federation::*;
}

/// Starts the web server with all configured routes.
#[tracing::instrument(skip(app_state, alert_state, app_resources))]
pub async fn start_webserver<P: ConnectionProvider>(
    app_state: AppState<P>,
    alert_state: AlertAppState,
    app_resources: AppResources,
    debug_mode: bool,
) -> color_eyre::Result<()> {
    // Build the base router with core endpoints
    let mut router = OpenApiRouter::with_openapi(openapi::ApiDoc::openapi())
        .nest(
            "/api/federation",
            federation::router::<P>(app_state, debug_mode),
        )
        .nest("/debug", debug::router())
        .routes(routes!(metrics::metrics));

    // Conditionally add legacy magic link alerts API
    if app_resources.config.oauth2.magic_links_enabled {
        router = router.nest("/api/alerts", alerts::router(alert_state));
        tracing::info!("Legacy magic link alerts API enabled at /api/alerts/*");
    } else {
        tracing::info!(
            "Legacy magic link alerts API disabled (oauth2.magic_links_enabled = false)"
        );
    }

    // Conditionally add OAuth2 endpoints if enabled
    if app_resources.config.oauth2.enabled {
        let oauth2_state = oauth2::OAuth2State::from_config(
            app_resources.db.clone(),
            &app_resources.config.oauth2,
        );
        router = router
            .nest("/oauth2", oauth2::router(oauth2_state))
            .nest("/api/v2/alerts", alerts_v2::router());
        tracing::info!("OAuth2 endpoints enabled at /oauth2/* and /api/v2/alerts/*");
    }

    // Apply middleware layers and finalize router
    let (router, api) = router
        // include trace context as header into the response
        .layer(OtelInResponseLayer)
        // start OpenTelemetry trace on incoming request
        .layer(OtelAxumLayer::default().try_extract_client_ip(true))
        .routes(routes!(health::health))
        // Attach application resources, CORS, our trace propagation middleware and the standard TraceLayer.
        .layer(axum::Extension(app_resources))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .split_for_parts();

    let router = router.merge(Redoc::with_url("/api-docs", api));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("Server running at 0.0.0.0:8080");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .map_err(|e| color_eyre::Report::msg(format!("Failed to start server: {e}")))?;

    Ok(())
}
