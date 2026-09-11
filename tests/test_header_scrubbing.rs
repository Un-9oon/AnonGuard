use anonguard::crypto::HeaderNormalizer;

#[test]
fn test_leak_header_scrubbing() {
    let mut headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("X-Forwarded-For".to_string(), "1.2.3.4".to_string()),
        ("Via".to_string(), "1.1 proxy".to_string()),
        ("User-Agent".to_string(), "test".to_string()),
    ];

    HeaderNormalizer::scrub_leak_headers(&mut headers);

    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].0, "Host");
    assert_eq!(headers[1].0, "User-Agent");
}

#[test]
fn test_chrome_header_ordering() {
    let mut headers = vec![
        ("Accept-Language".to_string(), "en-US".to_string()),
        ("Host".to_string(), "example.com".to_string()),
        ("User-Agent".to_string(), "test".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
    ];

    HeaderNormalizer::order_headers_chrome(&mut headers);

    // Order should be Host, Connection, User-Agent, Accept-Language
    assert_eq!(headers[0].0, "Host");
    assert_eq!(headers[1].0, "Connection");
    assert_eq!(headers[2].0, "User-Agent");
    assert_eq!(headers[3].0, "Accept-Language");
}
