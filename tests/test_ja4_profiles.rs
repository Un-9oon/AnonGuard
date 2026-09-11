use anonguard::crypto::TlsProfile;

#[test]
fn test_chrome_120_profile() {
    let profile = TlsProfile::chrome_120();
    assert_eq!(profile.name, "chrome_120");
    assert!(!profile.ja3_fingerprint.is_empty());
    assert!(!profile.ja4_fingerprint.is_empty());
    assert!(profile.cipher_suites.contains(&0x1301)); // TLS_AES_128_GCM_SHA256
}

#[test]
fn test_firefox_124_profile() {
    let profile = TlsProfile::firefox_124();
    assert_eq!(profile.name, "firefox_124");
    assert!(!profile.ja3_fingerprint.is_empty());
    assert!(!profile.ja4_fingerprint.is_empty());
    assert!(profile.cipher_suites.contains(&0x1301));
}
