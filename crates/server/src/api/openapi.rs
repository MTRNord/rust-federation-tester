//! OpenAPI/Utoipa configuration.

use crate::api::{alerts::ALERTS_TAG, federation::FEDERATION_TAG, health::MISC_TAG};
use crate::oauth2::OAUTH2_TAG;
use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, OAuth2, Scopes, SecurityScheme},
};

/// Security addon for OpenAPI documentation.
pub struct SecurityAddon;

impl Modify for SecurityAddon {
    #[tracing::instrument(skip(self, openapi))]
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            // JWT Bearer token (for legacy magic link auth)
            let bearer = HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("JWT")
                .description(Some(
                    "Use the JWT token obtained from the `/api/alerts/register` endpoint to authenticate.",
                ))
                .build();
            components.add_security_scheme("Authorization", SecurityScheme::Http(bearer));

            // OAuth2 Authorization Code flow
            let oauth2 = OAuth2::new([utoipa::openapi::security::Flow::AuthorizationCode(
                utoipa::openapi::security::AuthorizationCode::new(
                    "/oauth2/authorize",
                    "/oauth2/token",
                    Scopes::from_iter([
                        ("openid", "OpenID Connect scope"),
                        ("email", "Access to user email"),
                        ("profile", "Access to user profile"),
                        ("alerts:read", "Read alert subscriptions"),
                        ("alerts:write", "Manage alert subscriptions"),
                    ]),
                ),
            )]);
            components.add_security_scheme("OAuth2", SecurityScheme::OAuth2(oauth2));
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
        (name = ALERTS_TAG, description = "Alerts API endpoints"),
        (name = OAUTH2_TAG, description = "OAuth2 authentication endpoints")
    )
)]
pub struct ApiDoc;
