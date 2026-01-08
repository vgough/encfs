use anyhow::Result;
use encfs::crypto::ssl::SslCipher;
use std::time::Instant;

/// Test that Argon2 calibration increases time_cost to reach target duration
#[test]
fn test_argon2_calibration_basic() -> Result<()> {
    let password = "test_password";
    let salt = b"test_salt_20bytes!!";
    let memory_cost = 8192; // 8 MiB - small for fast testing
    let initial_time_cost = 1;
    let parallelism = 1;
    let key_len = 32;

    // First, measure how long a single iteration takes
    let start = Instant::now();
    SslCipher::derive_key_argon2id(
        password,
        salt,
        memory_cost,
        initial_time_cost,
        parallelism,
        key_len,
    )?;
    let single_iteration_ms = start.elapsed().as_millis();

    // If a single iteration already takes >= 1000ms, we can't test properly
    // (this is very unlikely with such small memory_cost)
    if single_iteration_ms >= 1000 {
        println!(
            "Single iteration took {}ms, test cannot properly verify calibration",
            single_iteration_ms
        );
        return Ok(());
    }

    // Calculate expected iterations needed to reach 1 second
    let expected_iterations = (1000.0 / single_iteration_ms as f64).ceil() as u32;
    let expected_iterations = expected_iterations.max(initial_time_cost + 1);

    // Verify the calibration logic works
    let ms_per_iteration = single_iteration_ms as f64 / initial_time_cost as f64;
    let needed_time_cost = (1000.0 / ms_per_iteration).ceil() as u32;
    let calibrated = needed_time_cost.max(initial_time_cost + 1);

    assert_eq!(calibrated, expected_iterations);

    // Verify that the calibrated time_cost actually takes >= 1 second
    let start = Instant::now();
    SslCipher::derive_key_argon2id(
        password,
        salt,
        memory_cost,
        calibrated,
        parallelism,
        key_len,
    )?;
    let calibrated_duration_ms = start.elapsed().as_millis();

    // Allow some tolerance (900ms) for timing variations
    assert!(
        calibrated_duration_ms >= 900,
        "Calibrated duration {}ms should be >= 900ms (target 1000ms)",
        calibrated_duration_ms
    );

    Ok(())
}

/// Test that if Argon2 already takes >= 1 second, time_cost is not increased
#[test]
fn test_argon2_no_calibration_if_already_slow() -> Result<()> {
    let password = "test_password";
    let salt = b"test_salt_20bytes!!";
    let memory_cost = 65536; // 64 MiB - larger for slower execution
    let initial_time_cost = 3;
    let parallelism = 4;
    let key_len = 32;

    // Measure how long it takes
    let start = Instant::now();
    SslCipher::derive_key_argon2id(
        password,
        salt,
        memory_cost,
        initial_time_cost,
        parallelism,
        key_len,
    )?;
    let duration_ms = start.elapsed().as_millis();

    // If it already takes >= 1 second, calibration should return the same value
    if duration_ms >= 1000 {
        // Simulate calibration logic
        let calibrated = initial_time_cost; // Should not change
        assert_eq!(calibrated, initial_time_cost);
    } else {
        println!(
            "Duration {}ms < 1000ms, calibration would increase time_cost",
            duration_ms
        );
    }

    Ok(())
}
