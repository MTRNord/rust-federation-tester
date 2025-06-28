use rust_federation_tester::cache::{DnsCache, VersionCache, WellKnownCache};
use rust_federation_tester::connection_pool::ConnectionPool;
use rust_federation_tester::response::WellKnownResult;
use std::time::Duration;
use tokio::time::sleep;

#[cfg(test)]
mod cache_tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_cache_basic_operations() {
        let cache = DnsCache::default();
        let key = "example.com".to_string();
        let value = vec!["192.168.1.1:8448".to_string(), "::1:8448".to_string()];

        // Test insert and get
        cache.insert(key.clone(), value.clone());
        assert_eq!(cache.get(&key), Some(value.clone()));

        // Test cache disabled get
        assert_eq!(cache.get_cached(&key, false), None);
        assert_eq!(cache.get_cached(&key, true), Some(value));

        // Test invalidate
        cache.invalidate(&key);
        assert_eq!(cache.get(&key), None);
    }

    #[tokio::test]
    async fn test_version_cache_serialization() {
        let cache = VersionCache::default();
        let key = "192.168.1.1:8448".to_string();
        let version_json = r#"{"name":"Synapse","version":"1.95.1"}"#.to_string();

        cache.insert(key.clone(), version_json.clone());
        assert_eq!(cache.get(&key), Some(version_json));
    }

    #[tokio::test]
    async fn test_well_known_cache() {
        let cache = WellKnownCache::default();
        let key = "example.com".to_string();
        let well_known = WellKnownResult {
            m_server: "matrix.example.com:443".to_string(),
            cache_expires_at: 1234567890,
            error: None,
        };

        cache.insert(key.clone(), well_known.clone());
        assert_eq!(cache.get(&key), Some(well_known));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        // Create cache with very short TTL for testing
        let cache = DnsCache::new(Duration::from_millis(10));
        let key = "example.com".to_string();
        let value = vec!["192.168.1.1:8448".to_string()];

        cache.insert(key.clone(), value.clone());
        assert_eq!(cache.get(&key), Some(value));

        // Wait for expiration
        sleep(Duration::from_millis(15)).await;
        assert_eq!(cache.get(&key), None);
    }

    #[tokio::test]
    async fn test_cache_concurrent_access() {
        let cache = DnsCache::default();
        let mut handles = Vec::new();

        // Spawn multiple tasks that insert and read from cache
        for i in 0..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                let key = format!("example{}.com", i);
                let value = vec![format!("192.168.1.{}:8448", i)];

                cache_clone.insert(key.clone(), value.clone());
                assert_eq!(cache_clone.get(&key), Some(value));
                i
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all entries are still there
        for i in 0..10 {
            let key = format!("example{}.com", i);
            let expected = vec![format!("192.168.1.{}:8448", i)];
            assert_eq!(cache.get(&key), Some(expected));
        }
    }
}

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

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_cache_performance() {
        let cache = DnsCache::default();
        let value = vec!["192.168.1.1:8448".to_string()];

        // Test insertion performance
        let start = Instant::now();
        for i in 0..1000 {
            cache.insert(format!("example{}.com", i), value.clone());
        }
        let insert_duration = start.elapsed();

        // Should be fast (less than 100ms for 1000 insertions)
        assert!(insert_duration < Duration::from_millis(100));

        // Test retrieval performance
        let start = Instant::now();
        for i in 0..1000 {
            let _ = cache.get(&format!("example{}.com", i));
        }
        let get_duration = start.elapsed();

        // Should be very fast (less than 50ms for 1000 retrievals)
        assert!(get_duration < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_concurrent_cache_performance() {
        let cache = DnsCache::default();
        let value = vec!["192.168.1.1:8448".to_string()];

        let start = Instant::now();
        let mut handles = Vec::new();

        // Test concurrent access performance
        for i in 0..100 {
            let cache_clone = cache.clone();
            let value_clone = value.clone();
            let handle = tokio::spawn(async move {
                let key = format!("example{}.com", i);
                cache_clone.insert(key.clone(), value_clone);
                cache_clone.get(&key)
            });
            handles.push(handle);
        }

        // Wait for all to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert_eq!(result, Some(value.clone()));
        }

        let duration = start.elapsed();

        // Should complete reasonably fast even with concurrent access
        assert!(duration < Duration::from_millis(500));
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_with_empty_values() {
        let cache = DnsCache::default();
        let key = "empty.com".to_string();
        let empty_value = vec![];

        cache.insert(key.clone(), empty_value.clone());
        assert_eq!(cache.get(&key), Some(empty_value));
    }

    #[tokio::test]
    async fn test_cache_with_unicode_keys() {
        let cache = DnsCache::default();
        let key = "example-ñ.com".to_string();
        let value = vec!["192.168.1.1:8448".to_string()];

        cache.insert(key.clone(), value.clone());
        assert_eq!(cache.get(&key), Some(value));
    }

    #[tokio::test]
    async fn test_cache_memory_usage() {
        let cache = DnsCache::default();

        // Insert many entries
        for i in 0..10000 {
            let key = format!("example{}.com", i);
            let value = vec![format!("192.168.1.{}:8448", i % 256)];
            cache.insert(key, value);
        }

        // Should handle large number of entries
        assert_eq!(cache.len(), 10000);

        // Clear cache
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
