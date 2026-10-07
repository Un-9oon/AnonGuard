//! Synthetic JA4 profile inventory model. These descriptors do not measure
//! transmitted ClientHello fingerprints or establish user anonymity.
//! Usage: cargo run --bin ja4-anonymity-calc -- --users <N>
use anonguard::crypto::ja4::TlsProfile;
use clap::Parser;
use std::collections::BTreeMap;

#[derive(Parser)]
#[command(about = "Model synthetic JA4 descriptor buckets; no anonymity guarantee")]
struct Args {
    #[arg(long, default_value_t = 10_000)]
    users: u64,
}

fn compute_k_anonymity(profile_count: usize, total_users: u64) -> f64 {
    if profile_count == 0 {
        return 0.0;
    }
    total_users as f64 / profile_count as f64
}

fn fingerprint_buckets(profiles: &[TlsProfile], total_users: u64) -> Vec<(String, usize, f64)> {
    let mut counts = BTreeMap::new();
    for profile in profiles {
        *counts
            .entry(profile.ja4_fingerprint.clone())
            .or_insert(0usize) += 1;
    }
    let per_profile = compute_k_anonymity(profiles.len(), total_users);
    counts
        .into_iter()
        .map(|(fingerprint, count)| (fingerprint, count, count as f64 * per_profile))
        .collect()
}

fn main() {
    let args = Args::parse();
    let profiles = TlsProfile::default_profiles();
    let buckets = fingerprint_buckets(&profiles, args.users);
    println!("=== Synthetic JA4 descriptor model ===");
    println!("Users modeled: {}", args.users);
    println!(
        "Profiles: {}; distinct descriptor fingerprints: {}",
        profiles.len(),
        buckets.len()
    );
    println!("Assumption: uniform profile selection, not uniform fingerprint selection.");
    println!(
        "Expected users per profile: {:.1}",
        compute_k_anonymity(profiles.len(), args.users)
    );
    for (fingerprint, count, users) in buckets {
        println!("Fingerprint {fingerprint} | profiles={count} | expected_users={users:.1}");
    }
    println!("Model only: profile labels are not measured on-wire TLS fingerprints.");
    println!("No anonymity guarantee or protection against traffic correlation is established.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_count_matches_grep() {
        // grep -n "chrome_\|firefox_\|safari_" src/crypto/ja4.rs shows:
        // chrome_120, chrome_124, firefox_124, firefox_128, safari_17 = 5 profiles
        let profiles = TlsProfile::default_profiles();
        assert_eq!(
            profiles.len(),
            5,
            "Expected 5 JA4 profiles (chrome_120, chrome_124, firefox_124, firefox_128, safari_17)"
        );
    }

    #[test]
    fn test_k_anonymity_calculation() {
        // k = 10,000 / 5 = 2,000
        let k = compute_k_anonymity(5, 10_000);
        assert!((k - 2000.0).abs() < 1e-9, "Expected k=2000.0, got {k}");

        // k = 1,000 / 5 = 200
        let k2 = compute_k_anonymity(5, 1_000);
        assert!((k2 - 200.0).abs() < 1e-9);

        // k = 0 when profile_count is 0 (division by zero guard)
        let k3 = compute_k_anonymity(0, 10_000);
        assert_eq!(k3, 0.0);
    }

    #[test]
    fn test_all_profiles_have_nonempty_ja4_fingerprint() {
        let profiles = TlsProfile::default_profiles();
        for p in profiles {
            assert!(
                !p.ja4_fingerprint.is_empty(),
                "Profile {} has empty JA4 fingerprint",
                p.name
            );
        }
    }

    #[test]
    fn fingerprint_collisions_are_grouped_with_profile_selection_weights() {
        let buckets = fingerprint_buckets(&TlsProfile::default_profiles(), 15);
        let mut counts: Vec<_> = buckets.iter().map(|(_, count, _)| *count).collect();
        counts.sort_unstable();
        assert_eq!(counts, vec![1, 2, 2]);
        let mut expected: Vec<_> = buckets.iter().map(|(_, _, users)| *users).collect();
        expected.sort_by(f64::total_cmp);
        assert_eq!(expected, vec![3.0, 6.0, 6.0]);
        assert_eq!(fingerprint_buckets(&[], 15), vec![]);
    }
}
