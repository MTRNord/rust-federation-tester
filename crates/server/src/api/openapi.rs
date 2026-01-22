//! OpenAPI/Utoipa configuration.

use crate::api::{alerts::ALERTS_TAG, federation::FEDERATION_TAG, health::MISC_TAG};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};

/// Security addon for OpenAPI documentation.
pub struct SecurityAddon;

impl Modify for SecurityAddon {
    #[tracing::instrument(skip(self, openapi))]
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            let bearer = HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("JWT")
                .description(Some(
                    "Use the JWT token obtained from the `/api/alerts/register` endpoint to authenticate.",
                ))
                .build();
            components.add_security_scheme("Authorization", SecurityScheme::Http(bearer));
        }
    }
}

/// OpenAPI documentation configuration.
#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    info(
        title = "Federation Tester API",
        version = "1.0.0",
        description = "API for testing Matrix federation compatibility of servers."
    ),
    tags(
        (name = MISC_TAG, description = "Miscellaneous endpoints"),
        (name = FEDERATION_TAG, description = "Federation Tester API endpoints"),
        (name = ALERTS_TAG, description = "Alerts API endpoints")
    )
)]
pub struct ApiDoc;
