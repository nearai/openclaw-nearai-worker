use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ApiError;

/// Manages one Docker Compose project per worker via the `docker compose` CLI.
pub struct ComposeManager {
    /// Path to the parameterized worker template (docker-compose.worker.yml).
    compose_file: PathBuf,
    /// Directory where per-user .env files are written (e.g. data/envs/).
    env_dir: PathBuf,
    /// Default OpenClaw image to pass as OPENCLAW_IMAGE.
    default_image: String,
}

impl ComposeManager {
    pub fn new(
        compose_file: PathBuf,
        env_dir: PathBuf,
        default_image: String,
    ) -> Result<Self, ApiError> {
        // Ensure the env directory exists
        std::fs::create_dir_all(&env_dir)
            .map_err(|e| ApiError::Internal(format!("Failed to create env dir: {}", e)))?;

        // Validate that the compose file exists
        if !compose_file.exists() {
            return Err(ApiError::Internal(format!(
                "Compose file not found: {}",
                compose_file.display()
            )));
        }

        Ok(Self {
            compose_file,
            env_dir,
            default_image,
        })
    }

    // ── env-file helpers ──────────────────────────────────────────────

    /// Write a per-user .env file consumed by docker-compose.worker.yml.
    pub fn write_env_file(
        &self,
        user_id: &str,
        vars: &HashMap<String, String>,
    ) -> Result<PathBuf, ApiError> {
        let path = self.env_dir.join(format!("{}.env", user_id));
        let content: String = vars
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, content)
            .map_err(|e| ApiError::Internal(format!("Failed to write env file: {}", e)))?;
        tracing::info!("Wrote env file for user {}", user_id);
        Ok(path)
    }

    pub fn remove_env_file(&self, user_id: &str) {
        let path = self.env_dir.join(format!("{}.env", user_id));
        let _ = std::fs::remove_file(path);
    }

    // ── compose lifecycle ─────────────────────────────────────────────

    /// `docker compose -p openclaw-{user_id} up -d`
    pub fn up(
        &self,
        user_id: &str,
        nearai_api_key: &str,
        token: &str,
        gateway_port: u16,
        ssh_port: u16,
        ssh_pubkey: Option<&str>,
    ) -> Result<(), ApiError> {
        let mut vars = HashMap::new();
        vars.insert("NEARAI_API_KEY".into(), nearai_api_key.into());
        vars.insert("OPENCLAW_GATEWAY_TOKEN".into(), token.into());
        vars.insert("GATEWAY_PORT".into(), gateway_port.to_string());
        vars.insert("SSH_PORT".into(), ssh_port.to_string());
        vars.insert("OPENCLAW_IMAGE".into(), self.default_image.clone());
        if let Some(pk) = ssh_pubkey {
            vars.insert("SSH_PUBKEY".into(), pk.into());
        }
        let env_path = self.write_env_file(user_id, &vars)?;

        self.compose_cmd(user_id, &env_path, &["up", "-d"])
    }

    /// `docker compose -p openclaw-{user_id} down -v` (removes volumes too)
    pub fn down(&self, user_id: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", user_id));
        self.compose_cmd(user_id, &env_path, &["down", "-v"])?;
        self.remove_env_file(user_id);
        Ok(())
    }

    pub fn stop(&self, user_id: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", user_id));
        self.compose_cmd(user_id, &env_path, &["stop"])
    }

    pub fn start(&self, user_id: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", user_id));
        self.compose_cmd(user_id, &env_path, &["start"])
    }

    pub fn restart(&self, user_id: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", user_id));
        self.compose_cmd(user_id, &env_path, &["restart"])
    }

    /// Returns the output of `docker compose ps --format json`.
    pub fn status(&self, user_id: &str) -> Result<String, ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", user_id));
        let project = format!("openclaw-{}", user_id);

        let output = Command::new("docker")
            .args([
                "compose",
                "-p",
                &project,
                "-f",
                self.compose_file.to_str().unwrap(),
                "--env-file",
                env_path.to_str().unwrap(),
                "ps",
                "--format",
                "json",
            ])
            .output()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker compose: {}", e)))?;

        if output.stdout.is_empty() {
            return Ok("not found".into());
        }

        // Parse JSON lines; each line is a service
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Look for the "State" field in JSON
        for line in stdout.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(state) = v.get("State").and_then(|s| s.as_str()) {
                    return Ok(state.to_string());
                }
            }
        }

        Ok("unknown".into())
    }

    // ── internal ──────────────────────────────────────────────────────

    fn compose_cmd(&self, user_id: &str, env_path: &Path, args: &[&str]) -> Result<(), ApiError> {
        let project = format!("openclaw-{}", user_id);

        let mut cmd = Command::new("docker");
        cmd.args([
            "compose",
            "-p",
            &project,
            "-f",
            self.compose_file.to_str().unwrap(),
            "--env-file",
            env_path.to_str().unwrap(),
        ]);
        cmd.args(args);

        let output = cmd
            .output()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker compose: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!(
                "docker compose failed: {}",
                stderr
            )));
        }

        Ok(())
    }
}
