// Tests for API components and infrastructure
use rust_federation_tester::connection_pool::ConnectionPool;

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
