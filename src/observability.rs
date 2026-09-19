//! Production Metrics & Observability Module.

use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Initializes the Prometheus metrics exporter on the specified socket address.
pub fn init_prometheus(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let builder = PrometheusBuilder::new().with_http_listener(addr);
    builder.install()?;
    tracing::info!("Prometheus metrics exporter listening on http://{}", addr);
    Ok(())
}

/// Increments the count of total circuits built.
pub fn inc_circuits_built() {
    metrics::counter!("circuits_built_total").increment(1);
}

/// Increments the count of total circuits torn down.
pub fn inc_circuits_torn_down() {
    metrics::counter!("circuits_torn_down_total").increment(1);
}

/// Increments the count of total cells processed.
pub fn inc_cells_processed() {
    metrics::counter!("cells_processed_total").increment(1);
}

/// Increments the count of killswitch trip events.
pub fn inc_killswitch_trips() {
    metrics::counter!("killswitch_trips_total").increment(1);
}

/// Increments the count of rejected Sybil PoW challenges.
pub fn inc_sybil_pow_rejected() {
    metrics::counter!("sybil_pow_rejected_total").increment(1);
}

/// Increments the count of failed quorum reconciliation attempts.
pub fn inc_quorum_reconciliation_failures() {
    metrics::counter!("quorum_reconciliation_failures_total").increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prometheus_metrics_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        if init_prometheus(addr).is_ok() {
            inc_killswitch_trips();

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let url = format!("http://{}/metrics", addr);
            let resp = reqwest_get_text(&url).await;
            assert!(
                resp.contains("killswitch_trips_total"),
                "Metrics output must contain killswitch_trips_total metric, got: {resp}"
            );
        }
    }

    async fn reqwest_get_text(url: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let host_port = url
            .trim_start_matches("http://")
            .trim_end_matches("/metrics");
        let mut stream = tokio::net::TcpStream::connect(host_port).await.unwrap();
        let req = format!(
            "GET /metrics HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host_port
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }
}
