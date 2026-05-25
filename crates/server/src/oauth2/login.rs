//! OAuth2 Login endpoints.
//!
//! - Login submission (POST)
//! - Magic link initiation (POST)
//!
//! The GET login page lives in the React frontend at /alerts/login.

use crate::entity::oauth2_user;
use crate::oauth2::{state::OAuth2State, verify_password};
use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Form data for login submission.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginForm {
    // OAuth2 flow parameters
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    // Login credentials
    pub email: String,
    pub password: Option<String>,
}

/// Creates the login router.
pub fn router() -> OpenApiRouter<OAuth2State> {
    OpenApiRouter::new().routes(routes!(login_submit))
}

/// Handle login form submission.
#[tracing::instrument(skip(state, form), fields(email = %form.email))]
#[utoipa::path(
    post,
    path = "/login",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Login Submit",
    summary = "Submit OAuth2 login credentials",
    description = "Authenticates the user with email and password. On success, creates an authorization code \
                   and redirects back to the client's redirect_uri.\n\n\
                   If the user has no password set (magic link only account), an appropriate error is shown.",
    request_body(
        content = LoginForm,
        content_type = "application/x-www-form-urlencoded",
        description = "Login credentials and OAuth2 flow parameters"
    ),
    responses(
        (status = 303, description = "Redirect to client with authorization code, or back to login with error"),
    )
)]
async fn login_submit(State(state): State<OAuth2State>, Form(form): Form<LoginForm>) -> Response {
    let frontend_url = state.frontend_url.trim_end_matches('/');
    let email = form.email.trim().to_lowercase();

    // Validate email format
    if email.is_empty() || !email.contains('@') {
        return redirect_to_login_with_error(
            &form,
            "Please enter a valid email address",
            frontend_url,
        );
    }

    // Look up user
    let user = match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::Email.eq(&email))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return redirect_to_login_with_error(&form, "Invalid email or password", frontend_url);
        }
        Err(e) => {
            tracing::error!("Database error looking up user: {}", e);
            return redirect_to_login_with_error(
                &form,
                "An error occurred. Please try again.",
                frontend_url,
            );
        }
    };

    // Check password
    let password = form.password.as_deref().unwrap_or("");

    if password.is_empty() {
        return redirect_to_login_with_error(&form, "Please enter your password", frontend_url);
    }

    // Verify password if user has one set
    match &user.password_hash {
        Some(hash) => {
            if !verify_password(password, hash) {
                return redirect_to_login_with_error(
                    &form,
                    "Invalid email or password",
                    frontend_url,
                );
            }
        }
        None => {
            return redirect_to_login_with_error(
                &form,
                "This account has no password set. Please create a new account with the same email address to link your existing alerts.",
                frontend_url,
            );
        }
    }

    // Check if email is verified (required for password login)
    if !user.email_verified {
        return redirect_to_login_with_error(
            &form,
            "Please verify your email address before signing in. Check your inbox for the verification link.",
            frontend_url,
        );
    }

    // Authentication successful - redirect to consent screen
    tracing::info!(email = %email, client_id = %form.client_id, "User authenticated successfully");

    let consent_url =
        super::consent::create_consent_redirect(super::consent::ConsentRedirectParams {
            user: &user,
            client_id: &form.client_id,
            redirect_uri: &form.redirect_uri,
            scope: &form.scope,
            state: &form.state,
            nonce: form.nonce.as_deref(),
            code_challenge: form.code_challenge.as_deref(),
            code_challenge_method: form.code_challenge_method.as_deref(),
        });

    Redirect::to(&consent_url).into_response()
}

/// Redirect back to the frontend login page with an error message.
fn redirect_to_login_with_error(form: &LoginForm, error: &str, frontend_url: &str) -> Response {
    let mut url = format!(
        "{}/alerts/login?client_id={}&redirect_uri={}&scope={}&state={}&error={}",
        frontend_url,
        urlencoding::encode(&form.client_id),
        urlencoding::encode(&form.redirect_uri),
        urlencoding::encode(&form.scope),
        urlencoding::encode(&form.state),
        urlencoding::encode(error),
    );

    // Preserve email for convenience
    if !form.email.is_empty() {
        url.push_str(&format!("&login_hint={}", urlencoding::encode(&form.email)));
    }

    // Preserve PKCE parameters
    if let Some(ref challenge) = form.code_challenge {
        url.push_str(&format!(
            "&code_challenge={}",
            urlencoding::encode(challenge)
        ));
    }
    if let Some(ref method) = form.code_challenge_method {
        url.push_str(&format!(
            "&code_challenge_method={}",
            urlencoding::encode(method)
        ));
    }
    if let Some(ref nonce) = form.nonce {
        url.push_str(&format!("&nonce={}", urlencoding::encode(nonce)));
    }

    Redirect::to(&url).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn make_form(email: &str) -> LoginForm {
        LoginForm {
            response_type: "code".to_string(),
            client_id: "my-client".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            scope: "openid".to_string(),
            state: "state-val".to_string(),
            nonce: Some("nonce-val".to_string()),
            code_challenge: Some("challenge-abc".to_string()),
            code_challenge_method: Some("S256".to_string()),
            email: email.to_string(),
            password: None,
        }
    }

    fn location(response: &axum::response::Response) -> String {
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    // ── redirect_to_login_with_error ──────────────────────────────────────────

    #[test]
    fn redirect_returns_303() {
        let form = make_form("alice@example.com");
        let resp = redirect_to_login_with_error(&form, "oops", "https://app.example.com");
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[test]
    fn redirect_encodes_error_in_location() {
        let form = make_form("alice@example.com");
        let resp = redirect_to_login_with_error(&form, "bad password", "https://app.example.com");
        let loc = location(&resp);
        assert!(
            loc.contains("error=bad%20password") || loc.contains("error=bad+password"),
            "loc: {loc}"
        );
    }

    #[test]
    fn redirect_preserves_oauth2_params() {
        let form = make_form("alice@example.com");
        let resp = redirect_to_login_with_error(&form, "err", "https://app.example.com");
        let loc = location(&resp);
        assert!(loc.contains("client_id=my-client"), "loc: {loc}");
        assert!(loc.contains("scope=openid"), "loc: {loc}");
        assert!(loc.contains("state=state-val"), "loc: {loc}");
    }

    #[test]
    fn redirect_preserves_email_as_login_hint() {
        let form = make_form("alice@example.com");
        let resp = redirect_to_login_with_error(&form, "err", "https://app.example.com");
        let loc = location(&resp);
        assert!(loc.contains("login_hint=alice"), "loc: {loc}");
    }

    #[test]
    fn redirect_preserves_pkce_params() {
        let form = make_form("alice@example.com");
        let resp = redirect_to_login_with_error(&form, "err", "https://app.example.com");
        let loc = location(&resp);
        assert!(loc.contains("code_challenge=challenge-abc"), "loc: {loc}");
        assert!(loc.contains("code_challenge_method=S256"), "loc: {loc}");
    }

    #[test]
    fn redirect_preserves_nonce() {
        let form = make_form("alice@example.com");
        let resp = redirect_to_login_with_error(&form, "err", "https://app.example.com");
        let loc = location(&resp);
        assert!(loc.contains("nonce=nonce-val"), "loc: {loc}");
    }

    #[test]
    fn redirect_no_login_hint_when_email_empty() {
        let form = make_form("");
        let resp = redirect_to_login_with_error(&form, "err", "https://app.example.com");
        let loc = location(&resp);
        assert!(
            !loc.contains("login_hint"),
            "expected no login_hint in: {loc}"
        );
    }

    #[test]
    fn redirect_no_pkce_when_none() {
        let mut form = make_form("alice@example.com");
        form.code_challenge = None;
        form.code_challenge_method = None;
        form.nonce = None;
        let resp = redirect_to_login_with_error(&form, "err", "https://app.example.com");
        let loc = location(&resp);
        assert!(!loc.contains("code_challenge="), "loc: {loc}");
        assert!(!loc.contains("nonce="), "loc: {loc}");
    }
}
