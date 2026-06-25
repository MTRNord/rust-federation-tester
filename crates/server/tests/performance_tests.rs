use bytes::Bytes;
use http_body_util::Empty;
use hyper::Request;
use rust_federation_tester::connection_pool::ConnectionPool;

fn make_test_req() -> Request<Empty<Bytes>> {
    Request::builder()
        .uri("/_matrix/federation/v1/version")
        .header(hyper::header::HOST, "example.com")
        .body(Empty::new())
        .unwrap()
}

#[cfg(test)]
mod connection_pool_tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let pool = ConnectionPool::new(10);
        assert_eq!(pool.pool_count(), 0);
    }

    #[tokio::test]
    async fn test_connection_pool_concurrent_access() {
        let pool = ConnectionPool::default();
        let mut handles = Vec::new();

        for i in 0..5 {
            let pool_clone = pool.clone();
            let handle = tokio::spawn(async move {
                let result = pool_clone
                    .send("127.0.0.1:8448", "example.com", make_test_req())
                    .await;
                assert!(result.is_err());
                i
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_connection_pool_cleanup() {
        let pool = ConnectionPool::default();
        pool.cleanup_dead_connections().await;
        let result = pool
            .send("127.0.0.1:8448", "example.com", make_test_req())
            .await;
        assert!(result.is_err());
    }
}
