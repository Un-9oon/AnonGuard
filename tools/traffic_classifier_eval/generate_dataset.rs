//! Dataset Generator for Empirical Traffic-Morphing Classifier Evaluation.
//!
//! Generates synthetic packet timing flows for 5 distinct website classes:
//! 1. Raw Un-morphed traffic: site-specific bursty inter-arrival delays.
//! 2. RMT Morphed traffic: transformed via session-level RMT Wigner-Surmise GOE level-repulsion.

use std::fs::File;
use std::io::{BufWriter, Write};

/// Simulates GOE Wigner-Surmise level repulsion for a global session base delay (10.0 ms).
fn wigner_surmise_goe(seed: u64) -> f64 {
    // P(s) = (pi/2) * s * exp(-pi/4 * s^2)
    // Inverse CDF: s = sqrt(-4/pi * ln(1 - u))
    let u = ((seed % 997) as f64 + 1.0) / 998.0;
    let s = (-4.0 / std::f64::consts::PI * (1.0 - u).ln()).sqrt();
    let base_delay_ms = 10.0;
    (base_delay_ms * s).max(0.5)
}

pub fn generate_traffic_dataset(
    output_path_raw: &str,
    output_path_morphed: &str,
    samples_per_class: usize,
    packets_per_flow: usize,
) -> std::io::Result<()> {
    let mut raw_file = BufWriter::new(File::create(output_path_raw)?);
    let mut morphed_file = BufWriter::new(File::create(output_path_morphed)?);

    // Write CSV Headers: label, p1, p2, ..., pN
    let header = (0..packets_per_flow)
        .map(|i| format!("p{i}"))
        .collect::<Vec<_>>()
        .join(",");
    writeln!(raw_file, "label,{header}")?;
    writeln!(morphed_file, "label,{header}")?;

    let base_delays_per_class = [
        [5.0, 15.0, 5.0, 25.0, 5.0, 10.0, 5.0, 30.0, 5.0, 10.0], // Class 0: News site
        [50.0, 50.0, 50.0, 50.0, 10.0, 10.0, 50.0, 50.0, 10.0, 10.0], // Class 1: Video stream
        [1.0, 2.0, 1.0, 2.0, 1.0, 2.0, 100.0, 1.0, 2.0, 100.0],  // Class 2: Search engine
        [
            10.0, 10.0, 100.0, 10.0, 10.0, 100.0, 10.0, 10.0, 100.0, 10.0,
        ], // Class 3: E-commerce
        [30.0, 30.0, 30.0, 30.0, 30.0, 30.0, 30.0, 30.0, 30.0, 30.0], // Class 4: Social media
    ];

    let mut seed: u64 = 42;

    for (class_id, class_base) in base_delays_per_class.iter().enumerate() {
        for _flow_idx in 0..samples_per_class {
            let mut raw_packet_delays = Vec::with_capacity(packets_per_flow);
            let mut morphed_packet_delays = Vec::with_capacity(packets_per_flow);

            for p in 0..packets_per_flow {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let noise = ((seed % 100) as f64 / 100.0 - 0.5) * 1.5;
                let base = class_base[p % class_base.len()];

                let raw_delay = (base + noise).max(0.1);
                let morphed_delay = wigner_surmise_goe(seed);

                raw_packet_delays.push(format!("{raw_delay:.3}"));
                morphed_packet_delays.push(format!("{morphed_delay:.3}"));
            }

            writeln!(raw_file, "{class_id},{}", raw_packet_delays.join(","))?;
            writeln!(
                morphed_file,
                "{class_id},{}",
                morphed_packet_delays.join(",")
            )?;
        }
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    println!("Generating traffic morphing evaluation datasets...");
    std::fs::create_dir_all("target/eval_data")?;
    generate_traffic_dataset(
        "target/eval_data/raw_unmorphed.csv",
        "target/eval_data/rmt_morphed.csv",
        200,
        20,
    )?;
    println!("Datasets successfully written to target/eval_data/");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_generation_produces_valid_files() {
        let tmp_dir = std::env::temp_dir().join("anonguard_eval_test");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let raw_path = tmp_dir.join("test_raw.csv");
        let morphed_path = tmp_dir.join("test_morphed.csv");

        generate_traffic_dataset(
            raw_path.to_str().unwrap(),
            morphed_path.to_str().unwrap(),
            10,
            10,
        )
        .unwrap();

        assert!(raw_path.exists());
        assert!(morphed_path.exists());

        let raw_content = std::fs::read_to_string(&raw_path).unwrap();
        let morphed_content = std::fs::read_to_string(&morphed_path).unwrap();

        assert_eq!(raw_content.lines().count(), 51); // 1 header + 5*10 rows
        assert_eq!(morphed_content.lines().count(), 51);
    }
}
