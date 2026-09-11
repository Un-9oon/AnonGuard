//! Deterministic HTTP header sequencing and leak header scrubbing.

use std::collections::HashSet;

pub const LEAK_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "x-forwarded-host",
    "x-forwarded-proto",
    "via",
    "forwarded",
    "cf-connecting-ip",
    "true-client-ip",
];

pub const CHROME_HEADER_ORDER: &[&str] = &[
    "host",
    "connection",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
];

pub struct HeaderNormalizer;

impl HeaderNormalizer {
    /// Scrubs headers known to leak proxy/client provenance.
    pub fn scrub_leak_headers(headers: &mut Vec<(String, String)>) {
        let leak_set: HashSet<&'static str> = LEAK_HEADERS.iter().copied().collect();
        headers.retain(|(key, _)| !leak_set.contains(key.to_lowercase().as_str()));
    }

    /// Sorts headers according to authentic Google Chrome binary order.
    pub fn order_headers_chrome(headers: &mut Vec<(String, String)>) {
        let order_map: std::collections::HashMap<&'static str, usize> = CHROME_HEADER_ORDER
            .iter()
            .enumerate()
            .map(|(idx, &k)| (k, idx))
            .collect();

        headers.sort_by_key(|(k, _)| {
            let lower = k.to_lowercase();
            order_map.get(lower.as_str()).copied().unwrap_or(999)
        });
    }
}
