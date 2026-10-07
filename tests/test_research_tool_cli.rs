//! Research-tool output must distinguish synthetic models from measured anonymity.
use std::time::Duration;
use tokio::process::Command;
async fn run(binary: &str, args: &[&str]) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(binary).args(args).kill_on_drop(true).output(),
    )
    .await
    .unwrap()
    .unwrap()
}
#[tokio::test]
async fn ja4_model_uses_requested_population_and_accounts_for_duplicate_descriptors() {
    let binary = env!("CARGO_BIN_EXE_ja4-anonymity-calc");
    for (args, population, expected) in [
        (vec!["--users", "15"], "15", vec![3.0, 6.0, 6.0]),
        (vec!["--users", "0"], "0", vec![0.0, 0.0, 0.0]),
    ] {
        let output = run(binary, &args).await;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains(&format!("Users modeled: {population}")));
        assert!(text.contains("Profiles: 5; distinct descriptor fingerprints: 3"));
        assert!(text.contains("not measured on-wire TLS fingerprints"));
        assert!(text.contains("No anonymity guarantee"));
        let mut values: Vec<f64> = text
            .lines()
            .filter_map(|line| {
                line.split_once("expected_users=")
                    .map(|(_, value)| value.parse().unwrap())
            })
            .collect();
        values.sort_by(f64::total_cmp);
        assert_eq!(values, expected);
    }
    assert!(!run(binary, &["--users", "invalid"]).await.status.success());
    let default = run(binary, &[]).await;
    assert!(default.status.success());
    assert!(String::from_utf8_lossy(&default.stdout).contains("Users modeled: 10000"));
}
#[tokio::test]
async fn entropy_demo_identifies_synthetic_inputs_and_reports_distribution_units() {
    let output = run(env!("CARGO_BIN_EXE_anonymity-set-calc"), &[]).await;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Synthetic inputs only"));
    assert!(text.contains("entropy does not establish anonymity"));
    assert!(text.contains("effective buckets = 10.00"));
    assert!(text.contains("Synthetic spread delays"));
    assert!(!text.contains("RMT Wigner"));
}

struct OutputDirectory(std::path::PathBuf);
impl Drop for OutputDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[tokio::test]
async fn dataset_cli_writes_complete_labeled_synthetic_flows_and_reports_output_failure() {
    let directory = OutputDirectory(
        std::env::temp_dir().join(format!("ag-dataset-cli-{:032x}", rand::random::<u128>())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let binary = env!("CARGO_BIN_EXE_generate-traffic-dataset");
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(binary)
            .current_dir(&directory.0)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Synthetic samples only"));
    for file in ["raw_unmorphed.csv", "rmt_morphed.csv"] {
        let text =
            std::fs::read_to_string(directory.0.join("target/eval_data").join(file)).unwrap();
        let mut rows = text.lines();
        assert_eq!(rows.next().unwrap().split(',').count(), 21);
        let mut labels = [0usize; 5];
        for row in rows {
            let values: Vec<_> = row.split(',').collect();
            assert_eq!(values.len(), 21);
            labels[values[0].parse::<usize>().unwrap()] += 1;
            for value in &values[1..] {
                let delay = value.parse::<f64>().unwrap();
                assert!(delay.is_finite() && delay > 0.0);
            }
        }
        assert_eq!(labels, [200; 5]);
    }
    let blocked = directory.0.join("blocked");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::write(blocked.join("target"), b"existing-file").unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(binary)
            .current_dir(&blocked)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(blocked.join("target")).unwrap(),
        b"existing-file"
    );
}
