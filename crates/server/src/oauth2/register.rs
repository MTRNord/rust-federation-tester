//! OAuth2 Registration endpoints.
//!
//! - Registration submission (POST)
//! - Email verification (GET)
//!
//! The GET registration page lives in the React frontend at /alerts/register.

use crate::AppResources;
use crate::email_templates::AccountVerificationEmailTemplate;
use crate::entity::oauth2_user;
use crate::oauth2::{
    generate_verification_token, hash_password, state::OAuth2State, validate_password_complexity,
};
use axum::{
    Extension, Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::{NotSet, Set},
    ColumnTrait, EntityTrait, QueryFilter,
};
use serde::Deserialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// Form data for registration submission.
#[derive(Clone, Debug, Deserialize, ToSchema)]
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
        .routes(routes!(register_submit))
        .routes(routes!(verify_email))
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
    let frontend_url = state.frontend_url.trim_end_matches('/');
    let email = form.email.trim().to_lowercase();

    // Validate email format
    if email.is_empty() || !email.contains('@') {
        return redirect_to_register_with_error(
            &form,
            "Please enter a valid email address",
            frontend_url,
        );
    }

    // Validate password complexity
    if let Err(msg) = validate_password_complexity(&form.password) {
        return redirect_to_register_with_error(&form, msg, frontend_url);
    }

    if form.password != form.password_confirm {
        return redirect_to_register_with_error(&form, "Passwords do not match", frontend_url);
    }

    // Check if user already exists
    match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::Email.eq(&email))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(existing_user)) => {
            if existing_user.email_verified && existing_user.password_hash.is_none() {
                // Magic-link account — user wants to add password login
                return upgrade_to_password_login(&state, &form, existing_user).await;
            } else if existing_user.email_verified {
                return redirect_to_register_with_error(
                    &form,
                    "An account with this email already exists. Please sign in instead.",
                    frontend_url,
                );
            } else if existing_user.has_pending_verification() {
                return resend_verification_or_error(&state, &resources, &form, existing_user)
                    .await;
            } else {
                return update_and_resend_verification(&state, &resources, &form, existing_user)
                    .await;
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("Database error checking existing user: {}", e);
            return redirect_to_register_with_error(
                &form,
                "An error occurred. Please try again.",
                frontend_url,
            );
        }
    }

    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            return redirect_to_register_with_error(
                &form,
                "An error occurred. Please try again.",
                frontend_url,
            );
        }
    };

    let verification_token = generate_verification_token();
    let now = OffsetDateTime::now_utc();
    let verification_expires = now + time::Duration::hours(24);

    let user = oauth2_user::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        email: Set(email.clone()),
        email_verified: Set(false),
        name: Set(None),
        receives_alerts: Set(true),
        created_at: Set(now),
        last_login_at: Set(None),
        password_hash: Set(Some(password_hash)),
        email_verification_token: Set(Some(verification_token.clone())),
        email_verification_expires_at: Set(Some(verification_expires)),
        password_reset_token: NotSet,
        password_reset_expires_at: NotSet,
        timezone: Set("UTC".to_string()),
    };

    if let Err(e) = user.insert(state.db.as_ref()).await {
        tracing::error!("Failed to create user: {}", e);
        return redirect_to_register_with_error(
            &form,
            "An error occurred. Please try again.",
            frontend_url,
        );
    }

    if let Err(e) = send_verification_email(&resources, &email, &verification_token, &form).await {
        tracing::error!("Failed to enqueue verification email: {}", e);
        return redirect_to_register_with_message(
            &form,
            "Account created but we couldn't queue the verification email. Please try again later.",
            frontend_url,
        );
    }

    tracing::info!(email = %email, "User registered, verification email queued");

    redirect_to_register_with_message(
        &form,
        "Account created! Please check your email for the verification link.",
        frontend_url,
    )
}

/// Set a password on an already-verified magic-link account.
///
/// The user is already verified (email_verified = true, password_hash = None), so
/// no verification email is sent — they can sign in immediately after this step.
async fn upgrade_to_password_login(
    state: &OAuth2State,
    form: &RegisterForm,
    user: oauth2_user::Model,
) -> Response {
    let frontend_url = state.frontend_url.trim_end_matches('/');
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password during upgrade: {}", e);
            return redirect_to_register_with_error(
                form,
                "An error occurred. Please try again.",
                frontend_url,
            );
        }
    };

    let mut active: oauth2_user::ActiveModel = user.into();
    active.password_hash = Set(Some(password_hash));

    if let Err(e) = active.update(state.db.as_ref()).await {
        tracing::error!("Failed to set password during magic-link upgrade: {}", e);
        return redirect_to_register_with_error(
            form,
            "An error occurred. Please try again.",
            frontend_url,
        );
    }

    tracing::info!(email = %form.email, "Magic-link account upgraded to password login");

    let login_url = format!(
        "{}/alerts/login?message={}&client_id={}&redirect_uri={}&scope={}&state={}&response_type={}&login_hint={}",
        frontend_url,
        urlencoding::encode("Password set successfully. You can now sign in."),
        urlencoding::encode(&form.client_id),
        urlencoding::encode(&form.redirect_uri),
        urlencoding::encode(&form.scope),
        urlencoding::encode(&form.state),
        urlencoding::encode(&form.response_type),
        urlencoding::encode(&form.email),
    );
    Redirect::to(&login_url).into_response()
}

/// Resend verification email for existing unverified user.
async fn resend_verification_or_error(
    state: &OAuth2State,
    resources: &AppResources,
    form: &RegisterForm,
    user: oauth2_user::Model,
) -> Response {
    let frontend_url = state.frontend_url.trim_end_matches('/');
    // Resend the existing verification email
    if let Some(token) = &user.email_verification_token {
        if let Err(e) = send_verification_email(resources, &user.email, token, form).await {
            tracing::error!("Failed to enqueue resend verification email: {}", e);
            return redirect_to_register_with_error(
                form,
                "Couldn't queue verification email. Please try again.",
                frontend_url,
            );
        }
        redirect_to_register_with_message(
            form,
            "A verification email has already been sent. We've sent it again - please check your inbox.",
            frontend_url,
        )
    } else {
        redirect_to_register_with_error(
            form,
            "An account with this email already exists. Please sign in instead.",
            frontend_url,
        )
    }
}

/// Update expired verification and resend email.
// tracing macros expand to `if` blocks that inflate the cognitive complexity
// score beyond what the three logical branches here actually warrant.
#[allow(clippy::cognitive_complexity)]
async fn update_and_resend_verification(
    state: &OAuth2State,
    resources: &AppResources,
    form: &RegisterForm,
    user: oauth2_user::Model,
) -> Response {
    let frontend_url = state.frontend_url.trim_end_matches('/');

    // Hash the new password
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Failed to hash password: {}", e);
            return redirect_to_register_with_error(
                form,
                "An error occurred. Please try again.",
                frontend_url,
            );
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
        return redirect_to_register_with_error(
            form,
            "An error occurred. Please try again.",
            frontend_url,
        );
    }

    if let Err(e) = send_verification_email(resources, &form.email, &verification_token, form).await
    {
        tracing::error!("Failed to enqueue verification email: {}", e);
        return redirect_to_register_with_error(
            form,
            "Couldn't queue verification email. Please try again.",
            frontend_url,
        );
    }

    redirect_to_register_with_message(
        form,
        "Your account has been updated. Please check your email for the verification link.",
        frontend_url,
    )
}

/// Enqueue the account verification email via the outbox.
async fn send_verification_email(
    resources: &AppResources,
    email: &str,
    token: &str,
    form: &RegisterForm,
) -> Result<(), sea_orm::DbErr> {
    // Build verification URL with OAuth2 parameters so the user can continue
    // the flow after clicking the link.
    let mut verify_url = format!(
        "{}/oauth2/verify-email?token={}",
        resources.config.oauth2.issuer_url.trim_end_matches('/'),
        urlencoding::encode(token)
    );
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

    let manage_url = Some(format!(
        "{}/account",
        resources.config.frontend_url.trim_end_matches('/')
    ));
    let sponsor_url = resources
        .config
        .github_sponsors_url
        .clone()
        .or_else(|| resources.config.liberapay_url.clone());
    let template = AccountVerificationEmailTemplate {
        verify_url,
        environment_name: resources.config.environment_name.clone(),
        recipient_email: email.to_string(),
        manage_url,
        sponsor_url,
    };

    let html_body = template.render_html().unwrap_or_default();
    let text_body = template.render_text();
    let subject = crate::email_templates::env_subject(
        "Verify your email - Federation Tester",
        resources.config.environment_name.as_deref(),
    );

    // Verification tokens expire in 24 h — no point delivering after that.
    let expires_at = OffsetDateTime::now_utc() + time::Duration::hours(24);

    crate::email_outbox::enqueue(
        resources.db.as_ref(),
        email,
        &subject,
        Some(html_body),
        text_body,
        Some(expires_at),
    )
    .await
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
    let frontend_url = state.frontend_url.trim_end_matches('/');

    let redirect_error = |msg: &str| {
        Redirect::to(&format!(
            "{}/alerts/login?error={}",
            frontend_url,
            urlencoding::encode(msg)
        ))
        .into_response()
    };

    // Find user by verification token
    let user = match oauth2_user::Entity::find()
        .filter(oauth2_user::Column::EmailVerificationToken.eq(&params.token))
        .one(state.db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return redirect_error("Invalid or expired verification link. Please register again.");
        }
        Err(e) => {
            tracing::error!("Database error during verification: {}", e);
            return redirect_error("An error occurred. Please try again.");
        }
    };

    // Check if token has expired
    if user.is_verification_expired() {
        return redirect_error(
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
        return redirect_error("An error occurred. Please try again.");
    }

    tracing::info!(email = %user.email, "User email verified successfully");

    // Redirect to frontend login page with success message and OAuth2 parameters
    let mut login_url = format!(
        "{}/alerts/login?message={}",
        frontend_url,
        urlencoding::encode("Email verified successfully. You can now sign in.")
    );

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
    if let Some(oauth2_state) = params.state {
        login_url.push_str(&format!("&state={}", urlencoding::encode(&oauth2_state)));
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

/// Redirect to the frontend registration page with an error message.
fn redirect_to_register_with_error(
    form: &RegisterForm,
    error: &str,
    frontend_url: &str,
) -> Response {
    let mut url = format!(
        "{}/alerts/register?client_id={}&redirect_uri={}&scope={}&state={}&response_type={}&error={}",
        frontend_url,
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

/// Redirect to the frontend registration page with a success message.
fn redirect_to_register_with_message(
    form: &RegisterForm,
    message: &str,
    frontend_url: &str,
) -> Response {
    let mut url = format!(
        "{}/alerts/register?client_id={}&redirect_uri={}&scope={}&state={}&response_type={}&message={}",
        frontend_url,
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
