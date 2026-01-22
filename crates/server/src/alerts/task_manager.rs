//! Alert task lifecycle management.
//!
//! Manages background tasks for recurring federation checks per alert.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;

/// Type alias for alert check task futures.
pub type AlertCheckTask = Pin<Box<dyn Future<Output = ()> + Send>>;

use std::future::Future;

/// Manages background tasks for recurring alert checks.
///
/// Each verified alert gets its own background task that periodically checks
/// the federation status. The task manager handles starting, stopping, and
/// tracking these tasks.
pub struct AlertTaskManager {
    pub(crate) running: RwLock<HashMap<i32, Arc<AtomicBool>>>,
}

impl Default for AlertTaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertTaskManager {
    /// Creates a new task manager.
    pub fn new() -> Self {
        Self {
            running: RwLock::new(HashMap::new()),
        }
    }

    /// Starts a new task for the given alert, or restarts it if already running.
    #[tracing::instrument(skip(self, f))]
    pub async fn start_or_restart_task<F>(&self, alert_id: i32, f: F)
    where
        F: FnOnce(Arc<AtomicBool>) -> AlertCheckTask + Send + 'static,
    {
        let mut running = self.running.write().await;
        if let Some(flag) = running.get(&alert_id) {
            flag.store(false, Ordering::SeqCst); // stop old
        }
        let flag = Arc::new(AtomicBool::new(true));
        running.insert(alert_id, flag.clone());
        let task = f(flag.clone());
        tokio::spawn(task);
    }

    /// Check if a task is already running for this alert.
    #[tracing::instrument(skip(self))]
    pub async fn is_running(&self, alert_id: i32) -> bool {
        let running = self.running.read().await;
        running.contains_key(&alert_id)
    }

    /// Stops the task for the given alert.
    #[tracing::instrument(skip(self))]
    pub async fn stop_task(&self, alert_id: i32) {
        let mut running = self.running.write().await;
        if let Some(flag) = running.remove(&alert_id) {
            flag.store(false, Ordering::SeqCst);
        }
    }

    /// Stops all running tasks.
    #[tracing::instrument(skip(self))]
    pub async fn stop_all(&self) {
        let mut running = self.running.write().await;
        for flag in running.values() {
            flag.store(false, Ordering::SeqCst);
        }
        running.clear();
    }
}
