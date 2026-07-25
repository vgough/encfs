#[path = "../benches/filesystem_support.rs"]
mod filesystem_support;

use filesystem_support::{
    BenchmarkResult, HostContext, SCHEMA_VERSION, Workload, calculate_deltas, ensure_compatible,
    load_result, parse_mdtest_output, save_result_atomic,
};

const CAPTURED_MDTEST_OUTPUT: &str = include_str!("fixtures/mdtest-summary.txt");

fn workload() -> Workload {
    Workload {
        ranks: 1,
        items_per_rank: 1_000,
        iterations: 5,
        bytes_per_file: 4_096,
    }
}

fn result_with_scale(scale: f64) -> BenchmarkResult {
    let (_, metrics) = parse_mdtest_output(CAPTURED_MDTEST_OUTPUT).unwrap();
    BenchmarkResult {
        schema_version: SCHEMA_VERSION,
        timestamp: "2026-07-15T21:20:39Z".to_string(),
        git_revision: "0123456789abcdef".to_string(),
        mdtest_version: "4.1.0+dev".to_string(),
        host: HostContext {
            os: "linux".to_string(),
            os_version: "6.12".to_string(),
            architecture: "x86_64".to_string(),
            cpu: "Example CPU".to_string(),
        },
        workload: workload(),
        metrics: metrics
            .into_iter()
            .map(|(name, value)| (name, value * scale))
            .collect(),
    }
}

#[test]
fn parses_captured_summary_and_mean_column() {
    let (version, metrics) = parse_mdtest_output(CAPTURED_MDTEST_OUTPUT).unwrap();
    assert_eq!(version, "4.1.0+dev");
    assert_eq!(metrics.len(), 10);
    assert_eq!(metrics["Directory creation"], 8264.638);
    assert_eq!(metrics["File read"], 13231.243);
}

#[test]
fn parses_legacy_summary_rows_with_a_colon() {
    let legacy = CAPTURED_MDTEST_OUTPUT.replace(
        "Directory creation           8264.638",
        "Directory creation        :  8264.638",
    );
    let (_, metrics) = parse_mdtest_output(&legacy).unwrap();
    assert_eq!(metrics["Directory creation"], 8264.638);
}

#[test]
fn rejects_malformed_summary_rows() {
    let malformed = CAPTURED_MDTEST_OUTPUT.replace(
        "File read                   13231.243      13231.243      13231.243          0.000",
        "File read                   13231.243      invalid        13231.243          0.000",
    );
    let error = parse_mdtest_output(&malformed).unwrap_err().to_string();
    assert!(error.contains("invalid numeric value"), "{error}");
}

#[test]
fn rejects_missing_required_metrics() {
    let incomplete = CAPTURED_MDTEST_OUTPUT
        .lines()
        .filter(|line| !line.trim_start().starts_with("Tree removal"))
        .collect::<Vec<_>>()
        .join("\n");
    let error = parse_mdtest_output(&incomplete).unwrap_err().to_string();
    assert!(error.contains("missing: Tree removal"), "{error}");
}

#[test]
fn json_round_trip_and_atomic_save_preserve_result() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/baseline.json");
    let expected = result_with_scale(1.0);
    save_result_atomic(&path, &expected).unwrap();
    let actual = load_result(&path).unwrap();
    assert_eq!(actual, expected);

    let replacement = result_with_scale(0.5);
    save_result_atomic(&path, &replacement).unwrap();
    assert_eq!(load_result(&path).unwrap(), replacement);

    let json = serde_json::to_string(&expected).unwrap();
    let round_trip: BenchmarkResult = serde_json::from_str(&json).unwrap();
    assert_eq!(round_trip, expected);
}

#[test]
fn rejects_incompatible_workloads() {
    let baseline = result_with_scale(1.0);
    let mut incompatible = workload();
    incompatible.items_per_rank = 10;
    let error = ensure_compatible(&baseline, &incompatible)
        .unwrap_err()
        .to_string();
    assert!(error.contains("workload does not match"), "{error}");
    assert!(error.contains("items/rank=1000"), "{error}");
    assert!(error.contains("items/rank=10"), "{error}");
}

#[test]
fn calculates_positive_and_negative_deltas_without_gating() {
    let baseline = result_with_scale(1.0);
    let mut current = result_with_scale(1.0);
    current
        .metrics
        .insert("Directory creation".to_string(), 10.0);
    let baseline_creation = baseline.metrics["Directory creation"];
    current.metrics.insert("File read".to_string(), 20_000.0);

    let deltas = calculate_deltas(&baseline, &current).unwrap();
    let creation = deltas
        .iter()
        .find(|delta| delta.name == "Directory creation")
        .unwrap();
    let read = deltas
        .iter()
        .find(|delta| delta.name == "File read")
        .unwrap();
    assert!(
        (creation.percent - ((10.0 - baseline_creation) / baseline_creation * 100.0)).abs() < 1e-9
    );
    assert!(creation.percent < 0.0);
    assert!(read.percent > 0.0);
}

#[test]
fn rejects_incomplete_metric_sets_during_comparison() {
    let baseline = result_with_scale(1.0);
    let mut current = result_with_scale(1.0);
    current.metrics.remove("Tree removal");
    let error = calculate_deltas(&baseline, &current)
        .unwrap_err()
        .to_string();
    assert!(error.contains("incomplete"), "{error}");
}

#[test]
fn supports_zero_baseline_delta_without_dividing_by_zero() {
    let mut baseline = result_with_scale(1.0);
    let mut current = result_with_scale(1.0);
    baseline.metrics.insert("File stat".to_string(), 0.0);
    current.metrics.insert("File stat".to_string(), 1.0);
    let deltas = calculate_deltas(&baseline, &current).unwrap();
    let stat = deltas
        .iter()
        .find(|delta| delta.name == "File stat")
        .unwrap();
    assert!(stat.percent.is_infinite());
}

#[test]
fn schema_mismatch_is_rejected() {
    let mut baseline = result_with_scale(1.0);
    baseline.schema_version += 1;
    let error = ensure_compatible(&baseline, &workload())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("unsupported filesystem benchmark schema"),
        "{error}"
    );
}

#[test]
fn extra_metrics_are_preserved_and_compared() {
    let mut baseline = result_with_scale(1.0);
    let mut current = result_with_scale(1.0);
    baseline
        .metrics
        .insert("Future operation".to_string(), 100.0);
    current
        .metrics
        .insert("Future operation".to_string(), 110.0);
    let deltas = calculate_deltas(&baseline, &current).unwrap();
    assert_eq!(
        deltas
            .iter()
            .find(|delta| delta.name == "Future operation")
            .unwrap()
            .percent,
        10.0
    );
}

#[test]
fn mismatched_metric_sets_are_rejected() {
    let mut baseline = result_with_scale(1.0);
    let current = result_with_scale(1.0);
    baseline.metrics.insert("Only in baseline".to_string(), 1.0);
    let error = calculate_deltas(&baseline, &current)
        .unwrap_err()
        .to_string();
    assert!(error.contains("metric sets differ"), "{error}");
}

#[test]
fn serde_rejects_non_numeric_metric_values() {
    let mut value = serde_json::to_value(result_with_scale(1.0)).unwrap();
    value["metrics"] = serde_json::json!({ "Directory creation": "fast" });
    assert!(serde_json::from_value::<BenchmarkResult>(value).is_err());
}
