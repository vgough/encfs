use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

/// Version 2 records which variant (see [`VARIANTS`]) the metrics measure;
/// version 1 measured the `encfsctl new` default of its day, unlabelled.
pub const SCHEMA_VERSION: u32 = 2;

/// The variant baselines record, tracking performance across revisions.
pub const BASELINE_VARIANT: &str = "no-unique-iv";

/// The variant compared against [`BASELINE_VARIANT`] within each run, to
/// show the overhead of per-directory name IVs.
pub const OVERHEAD_VARIANT: &str = "directory-iv";

/// A filesystem configuration the benchmark runs mdtest against.
pub struct Variant {
    /// Key in [`BenchmarkResult::variants`].
    pub name: &'static str,
    /// Extra `encfsctl new` arguments that create it.
    pub new_args: &'static [&'static str],
    /// Expected `directory_iv` and `unique_iv` of the created config, checked
    /// so a change of `encfsctl new` defaults can't silently swap what is
    /// being measured.
    pub directory_iv: bool,
    pub unique_iv: bool,
}

/// Every variant a comparison run measures.
pub const VARIANTS: [Variant; 2] = [
    // The `encfsctl new` default: per-directory name IVs, per-file IV headers.
    Variant {
        name: "directory-iv",
        new_args: &[],
        directory_iv: true,
        unique_iv: true,
    },
    // Headerless, path-chained names: the reverse-mode (encfsr) layout.
    Variant {
        name: "no-unique-iv",
        new_args: &["--no-unique-iv"],
        directory_iv: false,
        unique_iv: false,
    },
];

const REQUIRED_METRICS: [&str; 10] = [
    "Directory creation",
    "Directory stat",
    "Directory rename",
    "Directory removal",
    "File creation",
    "File stat",
    "File read",
    "File removal",
    "Tree creation",
    "Tree removal",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Workload {
    pub ranks: u32,
    pub items_per_rank: u64,
    pub iterations: u32,
    pub bytes_per_file: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostContext {
    pub os: String,
    pub os_version: String,
    pub architecture: String,
    pub cpu: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkResult {
    pub schema_version: u32,
    pub timestamp: String,
    pub git_revision: String,
    pub mdtest_version: String,
    pub host: HostContext,
    pub workload: Workload,
    /// Name of the [`Variant`] measured.
    pub variant: String,
    /// Mean ops/sec per mdtest operation.
    pub metrics: BTreeMap<String, f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetricDelta {
    pub name: String,
    pub baseline: f64,
    pub current: f64,
    pub percent: f64,
}

pub fn parse_mdtest_output(output: &str) -> Result<(String, BTreeMap<String, f64>)> {
    let version = output
        .lines()
        .find_map(|line| {
            let first = line.split_whitespace().next()?;
            (first.starts_with("mdtest-") && line.contains(" was launched"))
                .then(|| first.trim_start_matches("mdtest-").to_string())
        })
        .context("mdtest output did not contain its version banner")?;

    let lines: Vec<_> = output.lines().collect();
    let summary = lines
        .iter()
        .position(|line| line.trim_start().starts_with("SUMMARY rate"))
        .context("mdtest output did not contain a SUMMARY rate table")?;
    let header = lines[summary + 1..]
        .iter()
        .position(|line| line.contains("Operation") && line.contains("Mean"))
        .map(|offset| summary + 1 + offset)
        .context("mdtest SUMMARY rate table did not contain an Operation/Mean header")?;

    let mut metrics = BTreeMap::new();
    for line in &lines[header + 1..] {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("---------") {
            continue;
        }
        if trimmed.starts_with("-- finished") || trimmed.starts_with("SUMMARY ") {
            break;
        }

        let fields: Vec<_> = trimmed.split_whitespace().collect();
        if fields.len() < 5 {
            bail!("malformed mdtest summary row: {trimmed}");
        }
        let numeric_start = fields.len() - 4;
        let values = fields[numeric_start..]
            .iter()
            .map(|value| {
                value.parse::<f64>().with_context(|| {
                    format!("invalid numeric value {value:?} in mdtest summary row: {trimmed}")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if values
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
        {
            bail!("non-finite or negative value in mdtest summary row: {trimmed}");
        }

        let operation = fields[..numeric_start].join(" ");
        let name = operation.trim_end_matches(':').trim().to_string();
        if name.is_empty() {
            bail!("mdtest summary row has an empty operation name: {trimmed}");
        }
        if metrics.insert(name.clone(), values[2]).is_some() {
            bail!("mdtest summary contains duplicate operation {name:?}");
        }
    }

    if metrics.is_empty() {
        bail!("mdtest SUMMARY rate table contained no metrics");
    }
    let missing: Vec<_> = REQUIRED_METRICS
        .iter()
        .filter(|name| !metrics.contains_key(**name))
        .copied()
        .collect();
    if !missing.is_empty() {
        bail!(
            "mdtest SUMMARY rate table is incomplete; missing: {}",
            missing.join(", ")
        );
    }

    Ok((version, metrics))
}

pub fn validate_result(result: &BenchmarkResult) -> Result<()> {
    if result.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported filesystem benchmark schema {}; expected {}",
            result.schema_version,
            SCHEMA_VERSION
        );
    }
    if result.variant.is_empty() {
        bail!("filesystem benchmark result does not name its variant");
    }
    validate_metrics(&result.metrics)
}

pub fn validate_metrics(metrics: &BTreeMap<String, f64>) -> Result<()> {
    if metrics.is_empty() {
        bail!("filesystem benchmark result contains no metrics");
    }
    let missing: Vec<_> = REQUIRED_METRICS
        .iter()
        .filter(|name| !metrics.contains_key(**name))
        .copied()
        .collect();
    if !missing.is_empty() {
        bail!(
            "filesystem benchmark result is incomplete; missing: {}",
            missing.join(", ")
        );
    }
    if metrics
        .values()
        .any(|value| !value.is_finite() || *value < 0.0)
    {
        bail!("filesystem benchmark result contains an invalid metric value");
    }
    Ok(())
}

pub fn load_result(path: &Path) -> Result<BenchmarkResult> {
    let file = File::open(path)
        .with_context(|| format!("failed to open benchmark baseline {}", path.display()))?;
    let result: BenchmarkResult = serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("failed to parse benchmark baseline {}", path.display()))?;
    validate_result(&result)
        .with_context(|| format!("invalid benchmark baseline {}", path.display()))?;
    Ok(result)
}

pub fn save_result_atomic(path: &Path, result: &BenchmarkResult) -> Result<()> {
    validate_result(result)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create benchmark baseline directory {}",
            parent.display()
        )
    })?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "failed to create temporary benchmark baseline in {}",
            parent.display()
        )
    })?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        serde_json::to_writer_pretty(&mut writer, result)
            .context("failed to serialize benchmark result")?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace benchmark baseline {}", path.display()))?;
    Ok(())
}

/// Checks that `baseline` measured `variant` under `workload`.
pub fn ensure_compatible(
    baseline: &BenchmarkResult,
    variant: &str,
    workload: &Workload,
) -> Result<()> {
    validate_result(baseline)?;
    if baseline.variant != variant {
        bail!(
            "benchmark baseline measured variant {:?}, expected {:?}",
            baseline.variant,
            variant
        );
    }
    if baseline.workload != *workload {
        bail!(
            "benchmark workload does not match the baseline\n  baseline: {}\n  current:  {}",
            workload_description(&baseline.workload),
            workload_description(workload)
        );
    }
    Ok(())
}

/// Deltas of `current` against a baseline of the same variant and workload.
pub fn calculate_deltas(
    baseline: &BenchmarkResult,
    current: &BenchmarkResult,
) -> Result<Vec<MetricDelta>> {
    ensure_compatible(baseline, &current.variant, &current.workload)?;
    validate_result(current)?;
    compare_metrics(&baseline.metrics, &current.metrics)
}

/// Per-operation deltas of `current` relative to `baseline`; also used to
/// compare two variants measured in the same run.
pub fn compare_metrics(
    baseline: &BTreeMap<String, f64>,
    current: &BTreeMap<String, f64>,
) -> Result<Vec<MetricDelta>> {
    let baseline_names: BTreeSet<_> = baseline.keys().collect();
    let current_names: BTreeSet<_> = current.keys().collect();
    if baseline_names != current_names {
        let missing: Vec<_> = baseline_names.difference(&current_names).copied().collect();
        let added: Vec<_> = current_names.difference(&baseline_names).copied().collect();
        bail!(
            "benchmark metric sets differ (missing: {}; added: {})",
            display_names(&missing),
            display_names(&added)
        );
    }

    Ok(baseline
        .iter()
        .map(|(name, baseline_value)| {
            let current_value = current[name];
            let percent = if *baseline_value == 0.0 {
                if current_value == 0.0 {
                    0.0
                } else {
                    f64::INFINITY
                }
            } else {
                (current_value - baseline_value) / baseline_value * 100.0
            };
            MetricDelta {
                name: name.clone(),
                baseline: *baseline_value,
                current: current_value,
                percent,
            }
        })
        .collect())
}

pub fn workload_description(workload: &Workload) -> String {
    format!(
        "ranks={}, items/rank={}, iterations={}, bytes/file={}",
        workload.ranks, workload.items_per_rank, workload.iterations, workload.bytes_per_file
    )
}

fn display_names(names: &[&String]) -> String {
    if names.is_empty() {
        "none".to_string()
    } else {
        names
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}
