use rust_federation_tester::connection_pool::ConnectionPool;

#[cfg(test)]
mod connection_pool_tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let pool = ConnectionPool::new(5, 10);

        // Test that pool is created successfully
        // We can't easily test actual connections without a real server,
        // but we can test the basic structure
        assert_eq!(pool.len(), 0); // Should start empty
    }

    #[tokio::test]
    async fn test_connection_pool_concurrent_access() {
        let pool = ConnectionPool::default();
        let mut handles = Vec::new();

        // Test that multiple tasks can access the pool concurrently
        for i in 0..5 {
            let pool_clone = pool.clone();
            let handle = tokio::spawn(async move {
                // This will fail since we don't have a real server, but should not panic
                let result = pool_clone
                    .get_connection("127.0.0.1:8448", "example.com")
                    .await;
                // The connection should fail but not panic
                assert!(result.is_err());
                i
            });
            handles.push(handle);
        }

        // All tasks should complete without panicking
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_connection_pool_cleanup() {
        let pool = ConnectionPool::default();

        // Test cleanup function doesn't panic
        pool.cleanup_dead_connections().await;

        // Should still be able to use pool after cleanup
        let result = pool.get_connection("127.0.0.1:8448", "example.com").await;
        assert!(result.is_err()); // Expected to fail without real server
    }
}
