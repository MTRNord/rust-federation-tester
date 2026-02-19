//! Tests for alert system components.

use rust_federation_tester::alerts::{AlertTaskManager, should_send_failure_email};
use rust_federation_tester::entity::alert;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use time::{Duration, OffsetDateTime};

// =============================================================================
// AlertTaskManager Tests
// =============================================================================

#[tokio::test]
async fn test_task_manager_new() {
    let manager = AlertTaskManager::new();
    assert!(!manager.is_running(1).await);
}

#[tokio::test]
async fn test_task_manager_default() {
    let manager = AlertTaskManager::default();
    assert!(!manager.is_running(1).await);
}

#[tokio::test]
async fn test_task_manager_start_task() {
    let manager = Arc::new(AlertTaskManager::new());
    let flag_clone = Arc::new(AtomicBool::new(false));
    let flag_check = flag_clone.clone();

    manager
        .start_or_restart_task(42, move |flag| {
            Box::pin(async move {
                // Just record that we got a true flag
                flag_check.store(flag.load(Ordering::SeqCst), Ordering::SeqCst);
            })
        })
        .await;

    // Give task time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Task should be registered as running
    assert!(manager.is_running(42).await);
}

#[tokio::test]
async fn test_task_manager_stop_task() {
    let manager = AlertTaskManager::new();

    // Start a task that runs until stopped
    manager
        .start_or_restart_task(42, |flag| {
            Box::pin(async move {
                while flag.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            })
        })
        .await;

    assert!(manager.is_running(42).await);

    // Stop the task
    manager.stop_task(42).await;

    // Give the task time to see the flag change
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert!(!manager.is_running(42).await);
}

#[tokio::test]
async fn test_task_manager_stop_all() {
    let manager = AlertTaskManager::new();

    // Start multiple tasks
    for id in 1..=3 {
        let alert_id = id;
        manager
            .start_or_restart_task(alert_id, |flag| {
                Box::pin(async move {
                    while flag.load(Ordering::SeqCst) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                })
            })
            .await;
    }

    assert!(manager.is_running(1).await);
    assert!(manager.is_running(2).await);
    assert!(manager.is_running(3).await);

    // Stop all tasks
    manager.stop_all().await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert!(!manager.is_running(1).await);
    assert!(!manager.is_running(2).await);
    assert!(!manager.is_running(3).await);
}

#[tokio::test]
async fn test_task_manager_restart_replaces_task() {
    let manager = AlertTaskManager::new();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_clone = counter.clone();

    // Start first task
    manager
        .start_or_restart_task(42, move |flag| {
            let counter = counter_clone.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                while flag.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            })
        })
        .await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    let counter_clone2 = counter.clone();

    // Restart with new task
    manager
        .start_or_restart_task(42, move |flag| {
            let counter = counter_clone2.clone();
            Box::pin(async move {
                counter.fetch_add(10, Ordering::SeqCst);
                while flag.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            })
        })
        .await;

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Both tasks should have run
    let count = counter.load(Ordering::SeqCst);
    assert!(count >= 11, "Expected counter >= 11, got {}", count);
}

// =============================================================================
// should_send_failure_email Tests
// =============================================================================

fn create_test_alert(
    is_currently_failing: bool,
    last_email_sent_at: Option<OffsetDateTime>,
) -> alert::Model {
    create_test_alert_with_recovery(is_currently_failing, last_email_sent_at, None)
}

fn create_test_alert_with_recovery(
    is_currently_failing: bool,
    last_email_sent_at: Option<OffsetDateTime>,
    last_recovery_at: Option<OffsetDateTime>,
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
        failure_count: 0,
        is_currently_failing,
        last_recovery_at,
        user_id: None,
    }
}

#[test]
fn test_should_send_failure_email_first_failure() {
    let now = OffsetDateTime::now_utc();
    let alert = create_test_alert(false, None);

    // Server just started failing - should send email
    assert!(should_send_failure_email(&alert, now));
}

#[test]
fn test_should_send_failure_email_already_failing_no_email_sent() {
    let now = OffsetDateTime::now_utc();
    let alert = create_test_alert(true, None);

    // Server was already failing but no email sent yet - should send
    assert!(should_send_failure_email(&alert, now));
}

#[test]
fn test_should_send_failure_email_recent_email() {
    let now = OffsetDateTime::now_utc();
    // Email sent 1 hour ago (reminder interval is 24 hours)
    let last_email = now - Duration::hours(1);
    let alert = create_test_alert(true, Some(last_email));

    // Too soon for reminder - should NOT send
    assert!(!should_send_failure_email(&alert, now));
}

#[test]
fn test_should_send_failure_email_old_email() {
    let now = OffsetDateTime::now_utc();
    // Email sent 25 hours ago (reminder interval is 24 hours)
    let last_email = now - Duration::hours(25);
    let alert = create_test_alert(true, Some(last_email));

    // Past reminder threshold - should send
    assert!(should_send_failure_email(&alert, now));
}

#[test]
fn test_should_send_failure_email_exactly_at_threshold() {
    let now = OffsetDateTime::now_utc();
    // Email sent exactly 24 hours ago
    let last_email = now - Duration::hours(24);
    let alert = create_test_alert(true, Some(last_email));

    // At threshold - should send
    assert!(should_send_failure_email(&alert, now));
}

// =============================================================================
// Flapping Detection Tests
// =============================================================================

#[test]
fn test_flapping_suppression() {
    // Scenario: server failed, recovered 10 min ago, now failing again
    // Should NOT send a new failure email (flapping within 30 min window)
    let now = OffsetDateTime::now_utc();
    let last_recovery = now - Duration::minutes(10);
    let last_email = now - Duration::minutes(15); // email sent 15 min ago

    let alert = create_test_alert_with_recovery(false, Some(last_email), Some(last_recovery));

    assert!(
        !should_send_failure_email(&alert, now),
        "Should suppress failure email during flapping (recovered 10 min ago, email 15 min ago)"
    );
}

#[test]
fn test_flapping_after_stability_window() {
    // Scenario: server failed, recovered 35 min ago, now failing again
    // Should send a new failure email (past the 30 min stability window)
    let now = OffsetDateTime::now_utc();
    let last_recovery = now - Duration::minutes(35);
    let last_email = now - Duration::minutes(40);

    let alert = create_test_alert_with_recovery(false, Some(last_email), Some(last_recovery));

    assert!(
        should_send_failure_email(&alert, now),
        "Should send failure email after stability window has passed"
    );
}

#[test]
fn test_flapping_still_sends_reminder() {
    // Scenario: server is flapping, but it's been 13 hours since last email
    // Should send a reminder email even though we're in the flapping window
    let now = OffsetDateTime::now_utc();
    let last_recovery = now - Duration::minutes(10);
    let last_email = now - Duration::hours(13); // past the 12h reminder interval

    let alert = create_test_alert_with_recovery(false, Some(last_email), Some(last_recovery));

    assert!(
        should_send_failure_email(&alert, now),
        "Should send reminder email even during flapping when past reminder interval"
    );
}

#[test]
fn test_flapping_no_previous_email_sends_immediately() {
    // Scenario: server recovered recently but we never sent an email before
    // Should send because user has never been notified
    let now = OffsetDateTime::now_utc();
    let last_recovery = now - Duration::minutes(5);

    let alert = create_test_alert_with_recovery(false, None, Some(last_recovery));

    assert!(
        should_send_failure_email(&alert, now),
        "Should send failure email during flapping if no email was ever sent"
    );
}

#[test]
fn test_no_recovery_history_sends_normally() {
    // Scenario: first failure ever (no last_recovery_at)
    // Should send immediately - this is a genuine new failure
    let now = OffsetDateTime::now_utc();

    let alert = create_test_alert_with_recovery(false, None, None);

    assert!(
        should_send_failure_email(&alert, now),
        "Should send failure email on first-ever failure"
    );
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
        is_reminder: true,
        failure_count: 3,
        reminder_interval: "24 hours".to_string(),
        unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
        failure_reason: None,
    };

    let html = template.render_html().expect("render HTML");
    let text = template.render_text();

    // HTML should contain reminder-specific content
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
        is_reminder: false,
        failure_count: 1,
        reminder_interval: "24 hours".to_string(),
        unsubscribe_url: "https://test.example.com/unsubscribe?token=xyz".to_string(),
        failure_reason: None,
    };

    let text = template.render_text();

    // First failure - no reminder text
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
