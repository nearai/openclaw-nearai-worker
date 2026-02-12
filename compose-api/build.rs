use std::process::Command;

fn main() {
    // Git commit hash: prefer GIT_COMMIT env var (set by Docker build arg),
    // fall back to running git (works in local dev)
    let git_commit = std::env::var("GIT_COMMIT")
        .ok()
        .filter(|v| !v.is_empty() && v != "unknown")
        .unwrap_or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });

    // Build timestamp (UTC)
    let build_time = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
}
