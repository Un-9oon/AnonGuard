//! JA4 and JA3 TLS ClientHello fingerprint normalizer.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProfile {
    pub name: String,
    pub ja3_fingerprint: String,
    pub ja4_fingerprint: String,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub alpn: Vec<String>,
    pub user_agent: String,
}

impl TlsProfile {
    pub fn chrome_120() -> Self {
        Self {
            name: "chrome_120".to_string(),
            ja3_fingerprint: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0".to_string(),
            ja4_fingerprint: "t13d1516h2_8daaf6152771_0266399c6478".to_string(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, // ECDHE-ECDSA-AES128-GCM-SHA256
                0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
                0xc02c, // ECDHE-ECDSA-AES256-GCM-SHA384
                0xc030, // ECDHE-RSA-AES256-GCM-SHA384
                0xcca9, // ECDHE-ECDSA-CHACHA20-POLY1305
                0xcca8, // ECDHE-RSA-CHACHA20-POLY1305
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation (ALPN)
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x0012, // signed_certificate_timestamp
                0x0033, // key_share
                0x002d, // psk_key_exchange_modes
                0x002b, // supported_versions
            ],
            supported_groups: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
        }
    }

    pub fn chrome_124() -> Self {
        Self {
            name: "chrome_124".to_string(),
            ja3_fingerprint: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0".to_string(),
            ja4_fingerprint: "t13d1516h2_8daaf6152771_0266399c6478".to_string(),
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string(),
        }
    }

    pub fn firefox_124() -> Self {
        Self {
            name: "firefox_124".to_string(),
            ja3_fingerprint: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-43-45-51-27-21,29-23-24-25-256-257,0".to_string(),
            ja4_fingerprint: "t13d1715h2_e8f1e7e7833a_b556b6b72a6b".to_string(),
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b, 0x002d, 0x0033,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0".to_string(),
        }
    }

    pub fn firefox_128() -> Self {
        Self {
            name: "firefox_128".to_string(),
            ja3_fingerprint: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-43-45-51-27-21,29-23-24-25-256-257,0".to_string(),
            ja4_fingerprint: "t13d1715h2_e8f1e7e7833a_b556b6b72a6b".to_string(),
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b, 0x002d, 0x0033,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
        }
    }

    pub fn safari_17() -> Self {
        Self {
            name: "safari_17".to_string(),
            ja3_fingerprint: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0".to_string(),
            ja4_fingerprint: "t13d1516h2_a0e69123f124_0266399c6478".to_string(),
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0033, 0x002d, 0x002b,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15".to_string(),
        }
    }

    /// Looks up a TLS profile by name.
    ///
    /// NOTE: Maintaining an effective anti-fingerprinting set is an operational maintenance
    /// task. Fingerprint definitions (JA3/JA4, extensions, TLS versions) must be periodically
    /// refreshed as browser versions age out and real-world TLS stacks update.
    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "chrome_120" => Some(Self::chrome_120()),
            "chrome_124" => Some(Self::chrome_124()),
            "firefox_124" => Some(Self::firefox_124()),
            "firefox_128" => Some(Self::firefox_128()),
            "safari_17" => Some(Self::safari_17()),
            _ => None,
        }
    }

    /// Returns all supported default TLS profiles.
    pub fn default_profiles() -> Vec<Self> {
        vec![
            Self::chrome_120(),
            Self::chrome_124(),
            Self::firefox_124(),
            Self::firefox_128(),
            Self::safari_17(),
        ]
    }
}
