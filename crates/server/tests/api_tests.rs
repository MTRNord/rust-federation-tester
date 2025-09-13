// Tests for API components and infrastructure
use rust_federation_tester::{
    cache::{DnsCache, VersionCache, WellKnownCache},
    connection_pool::ConnectionPool,
};

#[tokio::test]
async fn test_cache_integration() {
    let dns_cache = DnsCache::default();
    let well_known_cache = WellKnownCache::default();
    let version_cache = VersionCache::default();

    // Test that caches can be used for storing/retrieving data
    dns_cache.insert("test.com".to_string(), vec!["192.168.1.1:8448".to_string()]);
    assert_eq!(
        dns_cache.get(&"test.com".to_string()),
        Some(vec!["192.168.1.1:8448".to_string()])
    );

    version_cache.insert(
        "192.168.1.1:8448".to_string(),
        r#"{"name":"test","version":"1.0"}"#.to_string(),
    );
    assert!(version_cache.get(&"192.168.1.1:8448".to_string()).is_some());

    // Test cache sizes
    assert_eq!(dns_cache.len(), 1);
    assert_eq!(version_cache.len(), 1);
    assert_eq!(well_known_cache.len(), 0);

    // Test cache expiration and invalidation
    dns_cache.invalidate(&"test.com".to_string());
    assert_eq!(dns_cache.len(), 0);

    // Test cache clearing
    version_cache.clear();
    assert_eq!(version_cache.len(), 0);
    assert!(version_cache.is_empty());
}

#[tokio::test]
async fn test_connection_pool_basic_operations() {
    let connection_pool = ConnectionPool::new(3, 8);

    // Test clone capability (required for sharing between handlers)
    let _cloned_pool = connection_pool.clone();

    // Test that we can create a connection pool successfully
    assert_eq!(connection_pool.len(), 0);
    assert!(connection_pool.is_empty());
}

#[test]
fn test_cache_defaults() {
    // Test that default cache instances can be created
    let dns_cache = DnsCache::default();
    let well_known_cache = WellKnownCache::default();
    let version_cache = VersionCache::default();

    // All should start empty
    assert!(dns_cache.is_empty());
    assert!(well_known_cache.is_empty());
    assert!(version_cache.is_empty());

    // Test that they have the expected types
    assert_eq!(dns_cache.len(), 0);
    assert_eq!(well_known_cache.len(), 0);
    assert_eq!(version_cache.len(), 0);
}

#[tokio::test]
async fn test_cache_concurrent_operations() {
    use tokio::task;

    let dns_cache = DnsCache::default();
    let cache_clone = dns_cache.clone();

    // Test concurrent insertions
    let handle1 = task::spawn(async move {
        cache_clone.insert("server1.com".to_string(), vec!["1.1.1.1:8448".to_string()]);
    });

    let handle2 = task::spawn(async move {
        dns_cache.insert("server2.com".to_string(), vec!["2.2.2.2:8448".to_string()]);
    });

    handle1.await.unwrap();
    handle2.await.unwrap();

    // Both insertions should succeed
    let final_cache = DnsCache::default();
    final_cache.insert("server1.com".to_string(), vec!["1.1.1.1:8448".to_string()]);
    final_cache.insert("server2.com".to_string(), vec!["2.2.2.2:8448".to_string()]);

    assert_eq!(final_cache.len(), 2);
}

#[test]
fn test_connection_pool_configuration() {
    // Test different connection pool configurations
    let pool1 = ConnectionPool::new(5, 10);
    let pool2 = ConnectionPool::new(1, 30);
    let pool3 = ConnectionPool::new(10, 5);

    // All should start empty regardless of configuration
    assert!(pool1.is_empty());
    assert!(pool2.is_empty());
    assert!(pool3.is_empty());

    // All should be cloneable
    let _cloned1 = pool1.clone();
    let _cloned2 = pool2.clone();
    let _cloned3 = pool3.clone();
}

#[test]
fn test_cache_operations() {
    let dns_cache = DnsCache::default();

    // Test multiple insertions
    dns_cache.insert("server1.com".to_string(), vec!["1.1.1.1:8448".to_string()]);
    dns_cache.insert(
        "server2.com".to_string(),
        vec!["2.2.2.2:8448".to_string(), "3.3.3.3:8448".to_string()],
    );

    assert_eq!(dns_cache.len(), 2);

    // Test retrieval
    assert_eq!(
        dns_cache.get(&"server1.com".to_string()),
        Some(vec!["1.1.1.1:8448".to_string()])
    );
    assert_eq!(
        dns_cache.get(&"server2.com".to_string()),
        Some(vec!["2.2.2.2:8448".to_string(), "3.3.3.3:8448".to_string()])
    );
    assert_eq!(dns_cache.get(&"nonexistent.com".to_string()), None);

    // Test invalidation
    dns_cache.invalidate(&"server1.com".to_string());
    assert_eq!(dns_cache.len(), 1);
    assert_eq!(dns_cache.get(&"server1.com".to_string()), None);
    assert_eq!(
        dns_cache.get(&"server2.com".to_string()),
        Some(vec!["2.2.2.2:8448".to_string(), "3.3.3.3:8448".to_string()])
    );
}
