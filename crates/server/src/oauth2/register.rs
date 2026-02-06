//! OAuth2 Registration endpoints.
//!
//! Implements user registration for the OAuth2 authorization flow:
//! - Registration page (GET)
//! - Registration submission (POST)
//! - Email verification (GET)

use crate::AppResources;
use crate::email_templates::AccountVerificationEmailTemplate;
use crate::entity::{oauth2_client, oauth2_user};
use crate::oauth2::{generate_verification_token, hash_password, state::OAuth2State};
use askama::Template;
use axum::{
    Extension, Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use lettre::AsyncTransport;
use lettre::message::{MultiPart, SinglePart};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Registration page template.
#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    // OAuth2 flow parameters
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    // Display information
    email: String,
    error: Option<String>,
    message: Option<String>,
    client_name: Option<String>,
}

/// Query parameters for the registration page.
#[derive(Debug, Deserialize)]
pub struct RegisterQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub email: Option<String>,
    pub error: Option<String>,
    pub message: Option<String>,
    pub response_type: Option<String>,
}

/// Form data for registration submission.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterForm {
    // OAuth2 flow parameters
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    // Registration data
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}

/// Query parameters for email verification.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
    // OAuth2 flow parameters to redirect after verification
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// Creates the registration router.
pub fn router() -> OpenApiRouter<OAuth2State> {
    OpenApiRouter::new()
        .routes(routes!(register_page))
        .routes(routes!(register_submit))
        .routes(routes!(verify_email))
}

/// Display the registration page.
#[tracing::instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/register",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Register Page",
    summary = "Display the OAuth2 registration page",
    description = "Renders the registration form for creating a new account during the OAuth2 authorization flow.\n\n\
                   Users register with email and password, then verify their email before they can sign in.",
    params(
        ("client_id" = String, Query, description = "The client identifier."),
        ("redirect_uri" = String, Query, description = "URI to redirect after authorization."),
        ("scope" = Option<String>, Query, description = "Space-separated list of requested scopes."),
        ("state" = Option<String>, Query, description = "Opaque value for CSRF protection."),
        ("nonce" = Option<String>, Query, description = "String value for replay protection."),
        ("code_challenge" = Option<String>, Query, description = "PKCE code challenge."),
        ("code_challenge_method" = Option<String>, Query, description = "PKCE challenge method."),
        ("email" = Option<String>, Query, description = "Email to pre-fill."),
        ("error" = Option<String>, Query, description = "Error message to display."),
        ("message" = Option<String>, Query, description = "Info message to display."),
        ("response_type" = Option<String>, Query, description = "OAuth2 response type."),
    ),
    responses(
        (status = 200, description = "Registration page HTML"),
        (status = 500, description = "Internal server error"),
    )
)]
async fn register_page(
    State(state): State<OAuth2State>,
    Query(params): Query<RegisterQuery>,
) -> Response {
    // Look up client for display name
    let client_name = match oauth2_client::Entity::find_by_id(&params.client_id)
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(c)) => Some(c.name),
        _ => None,
    };

    let template = RegisterTemplate {
        response_type: params.response_type.unwrap_or_else(|| "code".to_string()),
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: params.scope.unwrap_or_else(|| "openid".to_string()),
        state: params.state.unwrap_or_default(),
        nonce: params.nonce,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        email: params.email.unwrap_or_default(),
        error: params.error,
        message: params.message,
        client_name,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render registration template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

/// Handle registration form submission.
#[tracing::instrument(skip(state, resources, form), fields(email = %form.email))]
#[utoipa::path(
    post,
    path = "/register",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Register Submit",
    summary = "Submit OAuth2 registration",
    description = "Creates a new user account with email and password. A verification email is sent \
                   to the user. They must verify their email before they can sign in.\n\n\
                   If the email is already registered, the user is prompted to sign in instead.",
    request_body(
        content = RegisterForm,
        content_type = "application/x-www-form-urlencoded",
        description = "Registration data and OAuth2 flow parameters"
    ),
    responses(
        (status = 303, description = "Redirect back to registration page with success/error message"),
    )
)]
async fn register_submit(
    State(state): State<OAuth2State>,
    Extension(resources): Extension<AppResources>,
    Form(form): Form<RegisterForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();

    // Validate email format
    if email.is_empty() || !email.contains('@') {
        return redirect_to_register_with_error(&form, "Please enter a valid email address");
    }

    // Validate password
    if form.password.len() < 8 {
        return redirect_to_register_with_error(&form, "Password must be at least 8 characters");
    }

    if form.password != form.password_confirm {
        return redirect_to_register_with_error(&form, "Passwords do not match");
    }

    // Check if user already exists
    match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::Email.eq(&email))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(existing_user)) => {
            if existing_user.email_verified {
                // User already exists and is verified
                return redirect_to_register_with_error(
                    &form,
                    "An account with this email already exists. Please sign in instead.",
                );
            } else if existing_user.has_pending_verification() {
                // User exists but hasn't verified yet - resend verification email
                return resend_verification_or_error(&state, &resources, &form, existing_user)
                    .await;
            } else {
                // Verification expired - update user with new password and resend
                return update_and_resend_verification(&state, &resources, &form, existing_user)
                    .await;
            }
        }
        Ok(None) => {
            // Create new user
        }
        Err(e) => {
            tracing::error!("Database error checking existing user: {}", e);
            return redirect_to_register_with_error(&form, "An error occurred. Please try again.");
        }
    }

    // Hash the password
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            return redirect_to_register_with_error(&form, "An error occurred. Please try again.");
        }
    };

    // Generate verification token
    let verification_token = generate_verification_token();
    let now = OffsetDateTime::now_utc();
    let verification_expires = now + time::Duration::hours(24);

    // Create the user
    let user = oauth2_user::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        email: Set(email.clone()),
        email_verified: Set(false),
        name: Set(None),
        created_at: Set(now),
        last_login_at: Set(None),
        password_hash: Set(Some(password_hash)),
        email_verification_token: Set(Some(verification_token.clone())),
        email_verification_expires_at: Set(Some(verification_expires)),
    };

    if let Err(e) = user.insert(state.db.as_ref()).await {
        tracing::error!("Failed to create user: {}", e);
        return redirect_to_register_with_error(&form, "An error occurred. Please try again.");
    }

    // Send verification email
    if let Err(e) = send_verification_email(&resources, &email, &verification_token, &form).await {
        tracing::error!("Failed to send verification email: {}", e);
        // Don't fail registration, but warn the user
        return redirect_to_register_with_message(
            &form,
            "Account created but we couldn't send the verification email. Please try again later.",
        );
    }

    tracing::info!(email = %email, "User registered, verification email sent");

    // Redirect back to registration page with success message
    redirect_to_register_with_message(
        &form,
        "Account created! Please check your email for the verification link.",
    )
}

/// Resend verification email for existing unverified user.
async fn resend_verification_or_error(
    _state: &OAuth2State,
    resources: &AppResources,
    form: &RegisterForm,
    user: oauth2_user::Model,
) -> Response {
    // Resend the existing verification email
    if let Some(token) = &user.email_verification_token {
        if let Err(e) = send_verification_email(resources, &user.email, token, form).await {
            tracing::error!("Failed to resend verification email: {}", e);
            return redirect_to_register_with_error(
                form,
                "Couldn't send verification email. Please try again.",
            );
        }
        redirect_to_register_with_message(
            form,
            "A verification email has already been sent. We've sent it again - please check your inbox.",
        )
    } else {
        redirect_to_register_with_error(
            form,
            "An account with this email already exists. Please sign in instead.",
        )
    }
}

/// Update expired verification and resend email.
async fn update_and_resend_verification(
    state: &OAuth2State,
    resources: &AppResources,
    form: &RegisterForm,
    user: oauth2_user::Model,
) -> Response {
    // Hash the new password
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            return redirect_to_register_with_error(form, "An error occurred. Please try again.");
        }
    };

    // Generate new verification token
    let verification_token = generate_verification_token();
    let now = OffsetDateTime::now_utc();
    let verification_expires = now + time::Duration::hours(24);

    // Update the user
    let mut active: oauth2_user::ActiveModel = user.into();
    active.password_hash = Set(Some(password_hash));
    active.email_verification_token = Set(Some(verification_token.clone()));
    active.email_verification_expires_at = Set(Some(verification_expires));

    if let Err(e) = active.update(state.db.as_ref()).await {
        tracing::error!("Failed to update user: {}", e);
        return redirect_to_register_with_error(form, "An error occurred. Please try again.");
    }

    // Send verification email
    if let Err(e) = send_verification_email(resources, &form.email, &verification_token, form).await
    {
        tracing::error!("Failed to send verification email: {}", e);
        return redirect_to_register_with_error(
            form,
            "Couldn't send verification email. Please try again.",
        );
    }

    redirect_to_register_with_message(
        form,
        "Your account has been updated. Please check your email for the verification link.",
    )
}

/// Send the account verification email.
async fn send_verification_email(
    resources: &AppResources,
    email: &str,
    token: &str,
    form: &RegisterForm,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build verification URL with OAuth2 parameters
    let mut verify_url = format!(
        "{}/oauth2/verify-email?token={}",
        resources.config.frontend_url.trim_end_matches('/'),
        urlencoding::encode(token)
    );

    // Add OAuth2 parameters so user can continue after verification
    verify_url.push_str(&format!(
        "&client_id={}",
        urlencoding::encode(&form.client_id)
    ));
    verify_url.push_str(&format!(
        "&redirect_uri={}",
        urlencoding::encode(&form.redirect_uri)
    ));
    verify_url.push_str(&format!("&scope={}", urlencoding::encode(&form.scope)));
    verify_url.push_str(&format!("&state={}", urlencoding::encode(&form.state)));
    if let Some(ref nonce) = form.nonce {
        verify_url.push_str(&format!("&nonce={}", urlencoding::encode(nonce)));
    }
    if let Some(ref challenge) = form.code_challenge {
        verify_url.push_str(&format!(
            "&code_challenge={}",
            urlencoding::encode(challenge)
        ));
    }
    if let Some(ref method) = form.code_challenge_method {
        verify_url.push_str(&format!(
            "&code_challenge_method={}",
            urlencoding::encode(method)
        ));
    }

    let template = AccountVerificationEmailTemplate {
        verify_url: verify_url.clone(),
    };

    let html_body = template.render_html()?;
    let text_body = template.render_text();

    let email_msg = lettre::Message::builder()
        .from(resources.config.smtp.from.parse()?)
        .to(email.parse()?)
        .subject("Verify your email - Federation Tester")
        .header(lettre::message::header::MIME_VERSION_1_0)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(lettre::message::header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )?;

    resources.mailer.send(email_msg).await?;

    Ok(())
}

/// Handle email verification link.
#[tracing::instrument(skip(state))]
#[utoipa::path(
    get,
    path = "/verify-email",
    tag = super::OAUTH2_TAG,
    operation_id = "OAuth2 Verify Email",
    summary = "Verify email address from registration",
    description = "Handles the email verification link sent during registration. On success, \
                   redirects to the login page so the user can sign in with their new account.",
    params(
        ("token" = String, Query, description = "The email verification token."),
        ("client_id" = Option<String>, Query, description = "Client ID to continue the OAuth2 flow after verification."),
        ("redirect_uri" = Option<String>, Query, description = "Redirect URI to continue the OAuth2 flow."),
        ("scope" = Option<String>, Query, description = "Scopes to continue the OAuth2 flow."),
        ("state" = Option<String>, Query, description = "State to continue the OAuth2 flow."),
        ("nonce" = Option<String>, Query, description = "Nonce to continue the OAuth2 flow."),
        ("code_challenge" = Option<String>, Query, description = "PKCE code challenge to continue the OAuth2 flow."),
        ("code_challenge_method" = Option<String>, Query, description = "PKCE method to continue the OAuth2 flow."),
    ),
    responses(
        (status = 303, description = "Redirect to login page on success"),
        (status = 200, description = "Error page HTML on failure"),
    )
)]
async fn verify_email(
    State(state): State<OAuth2State>,
    Query(params): Query<VerifyEmailQuery>,
) -> Response {
    // Find user by verification token
    let user = match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::EmailVerificationToken.eq(&params.token))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return render_verification_error(
                "Invalid or expired verification link. Please register again.",
            );
        }
        Err(e) => {
            tracing::error!("Database error during verification: {}", e);
            return render_verification_error("An error occurred. Please try again.");
        }
    };

    // Check if token has expired
    if user.is_verification_expired() {
        return render_verification_error(
            "This verification link has expired. Please register again to get a new link.",
        );
    }

    // Mark email as verified and clear verification token
    let mut active: oauth2_user::ActiveModel = user.clone().into();
    active.email_verified = Set(true);
    active.email_verification_token = Set(None);
    active.email_verification_expires_at = Set(None);

    if let Err(e) = active.update(state.db.as_ref()).await {
        tracing::error!("Failed to verify user email: {}", e);
        return render_verification_error("An error occurred. Please try again.");
    }

    tracing::info!(email = %user.email, "User email verified successfully");

    // Redirect to login page with success message and OAuth2 parameters
    let mut login_url =
        "/oauth2/login?message=Email%20verified%20successfully.%20You%20can%20now%20sign%20in."
            .to_string();

    if let Some(client_id) = params.client_id {
        login_url.push_str(&format!("&client_id={}", urlencoding::encode(&client_id)));
    }
    if let Some(redirect_uri) = params.redirect_uri {
        login_url.push_str(&format!(
            "&redirect_uri={}",
            urlencoding::encode(&redirect_uri)
        ));
    }
    if let Some(scope) = params.scope {
        login_url.push_str(&format!("&scope={}", urlencoding::encode(&scope)));
    }
    if let Some(state) = params.state {
        login_url.push_str(&format!("&state={}", urlencoding::encode(&state)));
    }
    if let Some(nonce) = params.nonce {
        login_url.push_str(&format!("&nonce={}", urlencoding::encode(&nonce)));
    }
    if let Some(challenge) = params.code_challenge {
        login_url.push_str(&format!(
            "&code_challenge={}",
            urlencoding::encode(&challenge)
        ));
    }
    if let Some(method) = params.code_challenge_method {
        login_url.push_str(&format!(
            "&code_challenge_method={}",
            urlencoding::encode(&method)
        ));
    }
    login_url.push_str(&format!("&login_hint={}", urlencoding::encode(&user.email)));

    Redirect::to(&login_url).into_response()
}

/// Render an error page for verification failures.
fn render_verification_error(message: &str) -> Response {
    // Simple error page - in a real app you'd use a template
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Verification Failed - Federation Tester</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/govuk-frontend@5.14.0/dist/govuk/govuk-frontend.min.css">
</head>
<body class="govuk-template__body">
    <div class="govuk-width-container">
        <main class="govuk-main-wrapper" id="main-content">
            <div class="govuk-grid-row">
                <div class="govuk-grid-column-two-thirds">
                    <h1 class="govuk-heading-l">Verification failed</h1>
                    <p class="govuk-body">{}</p>
                    <p class="govuk-body">
                        <a class="govuk-link" href="/">Return to homepage</a>
                    </p>
                </div>
            </div>
        </main>
    </div>
</body>
</html>"#,
        message
    );
    Html(html).into_response()
}

/// Redirect back to registration page with an error message.
fn redirect_to_register_with_error(form: &RegisterForm, error: &str) -> Response {
    let mut url = format!(
        "/oauth2/register?client_id={}&redirect_uri={}&scope={}&state={}&response_type={}&error={}",
        urlencoding::encode(&form.client_id),
        urlencoding::encode(&form.redirect_uri),
        urlencoding::encode(&form.scope),
        urlencoding::encode(&form.state),
        urlencoding::encode(&form.response_type),
        urlencoding::encode(error),
    );

    // Preserve email for convenience
    if !form.email.is_empty() {
        url.push_str(&format!("&email={}", urlencoding::encode(&form.email)));
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

/// Redirect back to registration page with a success message.
fn redirect_to_register_with_message(form: &RegisterForm, message: &str) -> Response {
    let mut url = format!(
        "/oauth2/register?client_id={}&redirect_uri={}&scope={}&state={}&response_type={}&message={}",
        urlencoding::encode(&form.client_id),
        urlencoding::encode(&form.redirect_uri),
        urlencoding::encode(&form.scope),
        urlencoding::encode(&form.state),
        urlencoding::encode(&form.response_type),
        urlencoding::encode(message),
    );

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
