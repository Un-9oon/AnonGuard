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

#[test]
fn test_expanded_tls_profiles() {
    let profiles = TlsProfile::default_profiles();
    assert_eq!(profiles.len(), 5);

    for name in [
        "chrome_120",
        "chrome_124",
        "firefox_124",
        "firefox_128",
        "safari_17",
    ] {
        let p = TlsProfile::by_name(name).expect("Profile should exist");
        assert_eq!(p.name, name);
        assert!(!p.ja3_fingerprint.is_empty());
        assert!(!p.ja4_fingerprint.is_empty());
        assert!(!p.user_agent.is_empty());
    }

    assert!(TlsProfile::by_name("invalid_profile").is_none());
}
