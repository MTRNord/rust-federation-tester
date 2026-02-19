//! Tests for alert system components.

use rust_federation_tester::alerts::{
    CONFIRMATION_THRESHOLD, ConfirmationRegistry, should_send_reminder_email,
};
use rust_federation_tester::entity::alert;
use std::collections::HashMap;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

// =============================================================================
// Test helpers
// =============================================================================

fn make_alert(
    is_currently_failing: bool,
    last_email_sent_at: Option<OffsetDateTime>,
) -> alert::Model {
    alert::Model {
        id: 1,
        email: "test@example.com".to_string(),
        server_name: "example.org".to_string(),
        verified: true,
        magic_token: "token123".to_string(),
        created_at: OffsetDateTime::now_utc(),
        last_check_at: None,
        last_failure_at: None,
        last_success_at: None,
        last_email_sent_at,
        failure_count: if is_currently_failing { 1 } else { 0 },
        is_currently_failing,
        last_recovery_at: None,
        user_id: None,
    }
}

fn empty_registry() -> ConfirmationRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

// =============================================================================
// should_send_reminder_email Tests
// =============================================================================

#[test]
fn test_should_send_reminder_email_no_email_sent() {
    let now = OffsetDateTime::now_utc();
    let alert = make_alert(true, None);

    // No email has ever been sent → should send
    assert!(should_send_reminder_email(&alert, now));
}

#[test]
fn test_should_send_reminder_email_too_soon() {
    let now = OffsetDateTime::now_utc();
    // Email sent 1 hour ago (reminder interval is 12 hours)
    let last_email = now - Duration::hours(1);
    let alert = make_alert(true, Some(last_email));

    // Too soon for reminder → should NOT send
    assert!(!should_send_reminder_email(&alert, now));
}

#[test]
fn test_should_send_reminder_email_past_threshold() {
    let now = OffsetDateTime::now_utc();
    // Email sent 13 hours ago (reminder interval is 12 hours)
    let last_email = now - Duration::hours(13);
    let alert = make_alert(true, Some(last_email));

    // Past reminder threshold → should send
    assert!(should_send_reminder_email(&alert, now));
}

#[test]
fn test_should_send_reminder_email_at_threshold() {
    let now = OffsetDateTime::now_utc();
    // Email sent exactly 12 hours ago
    let last_email = now - Duration::hours(12);
    let alert = make_alert(true, Some(last_email));

    // At threshold → should send
    assert!(should_send_reminder_email(&alert, now));
}

#[test]
fn test_should_send_reminder_email_ignores_failing_flag() {
    // The function only cares about last_email_sent_at — is_currently_failing
    // is managed by the loop, not this predicate.
    let now = OffsetDateTime::now_utc();
    let alert_not_failing = make_alert(false, None);
    let alert_failing = make_alert(true, None);

    // Both return true when no email has been sent
    assert!(should_send_reminder_email(&alert_not_failing, now));
    assert!(should_send_reminder_email(&alert_failing, now));
}

// =============================================================================
// ConfirmationRegistry Tests
// =============================================================================

#[tokio::test]
async fn test_confirmation_registry_starts_empty() {
    let registry = empty_registry();
    let reg = registry.lock().await;
    assert!(reg.is_empty());
}

#[tokio::test]
async fn test_confirmation_no_email_before_threshold() {
    // Simulate the confirmation accumulation logic:
    // N-1 failures should not reach CONFIRMATION_THRESHOLD.
    let registry = empty_registry();

    // Insert an alert and accumulate failures up to threshold - 1
    {
        let mut reg = registry.lock().await;
        reg.insert(42, 1);
    }

    for step in 2..CONFIRMATION_THRESHOLD {
        let count = {
            let reg = registry.lock().await;
            reg.get(&42).copied().unwrap_or(0)
        };
        // Should still be below threshold
        assert!(
            count < CONFIRMATION_THRESHOLD,
            "Step {step}: count {count} should be < threshold"
        );
        // Increment
        let mut reg = registry.lock().await;
        reg.insert(42, step);
    }

    // At this point count == CONFIRMATION_THRESHOLD - 1, no email triggered yet
    let final_count = registry.lock().await.get(&42).copied().unwrap_or(0);
    assert_eq!(final_count, CONFIRMATION_THRESHOLD - 1);
}

#[tokio::test]
async fn test_confirmation_email_at_threshold() {
    // When count reaches CONFIRMATION_THRESHOLD the entry is removed and
    // is_currently_failing would be set to true (DB update done by loop).
    // Here we verify the registry removal logic.
    let registry = empty_registry();
    registry.lock().await.insert(42, CONFIRMATION_THRESHOLD - 1);

    // Simulate the threshold check that the active loop performs
    let new_count = {
        let reg = registry.lock().await;
        reg.get(&42).copied().unwrap_or(0) + 1
    };
    assert_eq!(new_count, CONFIRMATION_THRESHOLD);

    // Threshold reached → remove from registry (as the loop does)
    registry.lock().await.remove(&42);
    assert!(!registry.lock().await.contains_key(&42));
}

#[tokio::test]
async fn test_confirmation_recovery_cancels() {
    // If the server passes a check while in the confirmation phase,
    // the registry entry is removed and no email is sent.
    let registry = empty_registry();
    registry.lock().await.insert(42, 3);

    // Server passes → remove from registry
    let was_in_registry = registry.lock().await.remove(&42).is_some();
    assert!(was_in_registry);
    assert!(!registry.lock().await.contains_key(&42));
}

#[tokio::test]
async fn test_confirmation_threshold_constant() {
    // Ensure the constant matches the expected 5-minute window.
    assert_eq!(CONFIRMATION_THRESHOLD, 5);
}

// =============================================================================
// Email Template Tests
// =============================================================================

#[test]
fn test_failure_email_template_with_reminder() {
    use rust_federation_tester::email_templates::FailureEmailTemplate;

    let template = FailureEmailTemplate {
        server_name: "example.org".to_string(),
        check_url: "https://test.example.com/?serverName=example.org".to_string(),
        failure_count: 3,
        reminder_interval: "12 hours".to_string(),
        unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
        failure_reason: None,
    };

    let html = template.render_html().expect("render HTML");
    let text = template.render_text();

    // HTML should contain reminder-specific content (failure_count > 1)
    assert!(html.contains("reminder"));
    assert!(html.contains("example.org"));

    // Text should contain reminder info
    assert!(text.contains("reminder #3"));
    assert!(text.contains("failing for a while"));
}

#[test]
fn test_failure_email_template_without_reminder() {
    use rust_federation_tester::email_templates::FailureEmailTemplate;

    let template = FailureEmailTemplate {
        server_name: "example.org".to_string(),
        check_url: "https://test.example.com/?serverName=example.org".to_string(),
        failure_count: 1,
        reminder_interval: "12 hours".to_string(),
        unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
        failure_reason: None,
    };

    let text = template.render_text();

    // First failure — no reminder text
    assert!(!text.contains("reminder #"));
}

#[test]
fn test_recovery_email_template() {
    use rust_federation_tester::email_templates::RecoveryEmailTemplate;

    let template = RecoveryEmailTemplate {
        server_name: "example.org".to_string(),
        check_url: "https://test.example.com/?serverName=example.org".to_string(),
        unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
    };

    let html = template.render_html().expect("render HTML");
    let text = template.render_text();

    assert!(html.contains("example.org"));
    assert!(html.contains("recovered"));
    assert!(text.contains("Good news!"));
    assert!(text.contains("recovered"));
}

#[test]
fn test_verification_email_template() {
    use rust_federation_tester::email_templates::VerificationEmailTemplate;

    let template = VerificationEmailTemplate {
        server_name: "example.org".to_string(),
        verify_url: "https://test.example.com/verify?token=abc123".to_string(),
    };

    let html = template.render_html().expect("render HTML");
    let text = template.render_text();

    assert!(html.contains("example.org"));
    assert!(html.contains("abc123"));
    assert!(text.contains("verify"));
    assert!(text.contains("abc123"));
}
