use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ApiError;
use crate::store::Instance;

pub struct ContainerHealth {
    pub state: String,
    pub health: String,
}

/// Manages one Docker Compose project per worker via the `docker compose` CLI.
pub struct ComposeManager {
    /// Path to the parameterized worker template (docker-compose.worker.yml).
    compose_file: PathBuf,
    /// Directory where per-instance .env files are written (e.g. data/envs/).
    env_dir: PathBuf,
}

impl ComposeManager {
    pub fn new(compose_file: PathBuf, env_dir: PathBuf) -> Result<Self, ApiError> {
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
        })
    }

    // ── env-file helpers ──────────────────────────────────────────────

    /// Write a per-instance .env file consumed by docker-compose.worker.yml.
    pub fn write_env_file(
        &self,
        name: &str,
        vars: &HashMap<String, String>,
    ) -> Result<PathBuf, ApiError> {
        let path = self.env_dir.join(format!("{}.env", name));
        let content: String = vars
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, content)
            .map_err(|e| ApiError::Internal(format!("Failed to write env file: {}", e)))?;
        tracing::info!("Wrote env file for instance {}", name);
        Ok(path)
    }

    pub fn remove_env_file(&self, name: &str) {
        let path = self.env_dir.join(format!("{}.env", name));
        let _ = std::fs::remove_file(path);
    }

    // ── compose lifecycle ─────────────────────────────────────────────

    /// `docker compose -p openclaw-{name} up -d --pull always`
    pub fn up(
        &self,
        name: &str,
        nearai_api_key: &str,
        token: &str,
        gateway_port: u16,
        ssh_port: u16,
        ssh_pubkey: &str,
        image: &str,
    ) -> Result<(), ApiError> {
        let mut vars = HashMap::new();
        vars.insert("NEARAI_API_KEY".into(), nearai_api_key.into());
        vars.insert("OPENCLAW_GATEWAY_TOKEN".into(), token.into());
        vars.insert("GATEWAY_PORT".into(), gateway_port.to_string());
        vars.insert("SSH_PORT".into(), ssh_port.to_string());
        vars.insert("OPENCLAW_IMAGE".into(), image.to_string());
        vars.insert("SSH_PUBKEY".into(), ssh_pubkey.into());
        let env_path = self.write_env_file(name, &vars)?;

        // Pull from registry for remote images (contain '/') or digest-pinned references;
        // local-only images (no '/') use --pull never
        let pull_policy = if image.contains('/') || image.contains("@sha256:") {
            "always"
        } else {
            "never"
        };
        self.compose_cmd(
            name,
            &env_path,
            &["up", "-d", "--pull", pull_policy],
            Some(&vars),
        )
    }

    /// `docker compose -p openclaw-{name} down -v` (removes volumes too)
    pub fn down(&self, name: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", name));
        self.compose_cmd(name, &env_path, &["down", "-v"], None)?;
        self.remove_env_file(name);
        Ok(())
    }

    pub fn stop(&self, name: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", name));
        self.compose_cmd(name, &env_path, &["stop"], None)
    }

    pub fn start(&self, name: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", name));
        self.compose_cmd(name, &env_path, &["start"], None)
    }

    pub fn restart(&self, name: &str) -> Result<(), ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", name));
        self.compose_cmd(name, &env_path, &["restart"], None)
    }

    /// Returns the output of `docker compose ps --format json`.
    pub fn status(&self, name: &str) -> Result<String, ApiError> {
        let env_path = self.env_dir.join(format!("{}.env", name));
        let project = format!("openclaw-{}", name);

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

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(state) = v.get("State").and_then(|s| s.as_str()) {
                    return Ok(state.to_string());
                }
            }
        }

        Ok("unknown".into())
    }

    // ── health polling ────────────────────────────────────────────────

    /// Query the Docker container health state for an instance's gateway container.
    pub fn container_health(&self, name: &str) -> Result<ContainerHealth, ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);
        let output = Command::new("docker")
            .args([
                "inspect",
                &container,
                "--format",
                "{{.State.Status}}|{{.State.Health.Status}}",
            ])
            .output()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker inspect: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such object") {
                return Ok(ContainerHealth {
                    state: "not_found".into(),
                    health: "none".into(),
                });
            }
            return Err(ApiError::Internal(format!(
                "docker inspect failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let parts: Vec<&str> = stdout.splitn(2, '|').collect();
        Ok(ContainerHealth {
            state: parts.first().unwrap_or(&"unknown").to_string(),
            health: parts.get(1).unwrap_or(&"none").to_string(),
        })
    }

    /// Resolve the registry digest for an instance's gateway container image.
    /// Returns e.g. `docker.io/openclaw/worker@sha256:abcdef...` or `None` for local-only images.
    pub fn resolve_image_digest(&self, name: &str) -> Option<String> {
        let container = format!("openclaw-{}-gateway-1", name);

        // Get the image ID from the running container
        let output = Command::new("docker")
            .args(["inspect", &container, "--format", "{{.Image}}"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let image_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if image_id.is_empty() {
            return None;
        }

        // Get the RepoDigests from the image
        let output = Command::new("docker")
            .args(["inspect", &image_id, "--format", "{{json .RepoDigests}}"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let digests: Vec<String> = serde_json::from_str(&stdout).ok()?;
        digests.into_iter().next()
    }

    // ── instance data export ────────────────────────────────────────────

    /// Export both the config volume (`.openclaw/`) and workspace volume (`openclaw/`)
    /// from an instance's gateway container as a single tar archive.
    /// Uses `docker exec tar` to capture both directories relative to `/home/agent/`.
    pub fn export_instance_data(&self, name: &str) -> Result<Vec<u8>, ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);
        let output = Command::new("docker")
            .args([
                "exec",
                &container,
                "tar",
                "cf",
                "-",
                "-C",
                "/home/agent",
                ".openclaw",
                "openclaw",
            ])
            .output()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker exec tar: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!(
                "docker exec tar failed: {}",
                stderr
            )));
        }

        Ok(output.stdout)
    }

    // ── discovery ─────────────────────────────────────────────────────

    /// Discover all managed instances from Docker containers.
    /// Uses the `openclaw.managed=true` label to find gateway containers,
    /// then inspects each to rebuild Instance structs.
    pub fn discover_instances(&self) -> Result<Vec<Instance>, ApiError> {
        let output = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                "label=openclaw.managed=true",
                "--format",
                "{{.Names}}",
            ])
            .output()
            .map_err(|e| ApiError::Internal(format!("failed to run docker ps: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!("docker ps failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut instances = Vec::new();

        for line in stdout.lines() {
            let container_name = line.trim();
            if container_name.is_empty() {
                continue;
            }

            // Match pattern: openclaw-{name}-gateway-1
            let name = match container_name
                .strip_prefix("openclaw-")
                .and_then(|s| s.strip_suffix("-gateway-1"))
            {
                Some(n) => n.to_string(),
                None => {
                    tracing::debug!("skipping non-gateway container: {}", container_name);
                    continue;
                }
            };

            match self.inspect_container(container_name) {
                Ok(inst) => instances.push(inst),
                Err(e) => {
                    tracing::warn!(
                        "failed to inspect container {} (instance {}): {}",
                        container_name,
                        name,
                        e
                    );
                }
            }
        }

        Ok(instances)
    }

    /// Inspect a single container and build an Instance from its metadata.
    fn inspect_container(&self, container_name: &str) -> Result<Instance, ApiError> {
        let output = Command::new("docker")
            .args(["inspect", container_name, "--format", "{{json .}}"])
            .output()
            .map_err(|e| ApiError::Internal(format!("failed to run docker inspect: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!(
                "docker inspect failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let v: serde_json::Value = serde_json::from_str(stdout.trim()).map_err(|e| {
            ApiError::Internal(format!("failed to parse docker inspect json: {}", e))
        })?;

        // Extract instance name from container name: openclaw-{name}-gateway-1
        let name = container_name
            .strip_prefix("openclaw-")
            .and_then(|s| s.strip_suffix("-gateway-1"))
            .ok_or_else(|| {
                ApiError::Internal(format!("unexpected container name: {}", container_name))
            })?
            .to_string();

        // Parse env vars from .Config.Env (array of "KEY=VALUE" strings)
        let env_map: HashMap<String, String> = v
            .pointer("/Config/Env")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str())
                    .filter_map(|s| s.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let token = env_map
            .get("OPENCLAW_GATEWAY_TOKEN")
            .cloned()
            .unwrap_or_default();
        let ssh_pubkey = env_map.get("SSH_PUBKEY").cloned().unwrap_or_default();
        let nearai_api_key = env_map.get("NEARAI_API_KEY").cloned().unwrap_or_default();
        let image_env = env_map.get("OPENCLAW_IMAGE").cloned();

        // Parse port bindings from .HostConfig.PortBindings
        let port_bindings = v.pointer("/HostConfig/PortBindings");
        let gateway_port = Self::extract_host_port(port_bindings, "18789/tcp").unwrap_or(0);
        let ssh_port = Self::extract_host_port(port_bindings, "2222/tcp").unwrap_or(0);

        // Parse created_at from .Created
        let created_at = v
            .get("Created")
            .and_then(|c| c.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);

        // Determine active state from .State.Status
        let active = v
            .pointer("/State/Status")
            .and_then(|s| s.as_str())
            .map(|s| s == "running")
            .unwrap_or(false);

        // Resolve image: prefer env var, fall back to container config
        let image = image_env.or_else(|| {
            v.pointer("/Config/Image")
                .and_then(|i| i.as_str())
                .map(|s| s.to_string())
        });

        // Resolve image digest from .Image → RepoDigests
        let image_digest = self.resolve_image_digest(&name);

        Ok(Instance {
            name,
            token,
            gateway_port,
            ssh_port,
            created_at,
            ssh_pubkey,
            nearai_api_key,
            active,
            image,
            image_digest,
        })
    }

    /// Extract a host port number from PortBindings JSON.
    fn extract_host_port(
        port_bindings: Option<&serde_json::Value>,
        container_port: &str,
    ) -> Option<u16> {
        port_bindings?
            .get(container_port)?
            .as_array()?
            .first()?
            .get("HostPort")?
            .as_str()?
            .parse()
            .ok()
    }

    /// Reconstruct the env file for a discovered instance so that
    /// docker compose lifecycle commands (stop/start/restart) continue to work.
    pub fn ensure_env_file(&self, inst: &Instance) -> Result<PathBuf, ApiError> {
        let mut vars = HashMap::new();
        vars.insert("NEARAI_API_KEY".into(), inst.nearai_api_key.clone());
        vars.insert("OPENCLAW_GATEWAY_TOKEN".into(), inst.token.clone());
        vars.insert("GATEWAY_PORT".into(), inst.gateway_port.to_string());
        vars.insert("SSH_PORT".into(), inst.ssh_port.to_string());
        vars.insert("SSH_PUBKEY".into(), inst.ssh_pubkey.clone());
        if let Some(ref image) = inst.image {
            vars.insert("OPENCLAW_IMAGE".into(), image.clone());
        }
        self.write_env_file(&inst.name, &vars)
    }

    // ── internal ──────────────────────────────────────────────────────

    fn compose_cmd(
        &self,
        name: &str,
        env_path: &Path,
        args: &[&str],
        env_vars: Option<&HashMap<String, String>>,
    ) -> Result<(), ApiError> {
        let project = format!("openclaw-{}", name);

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
        if let Some(vars) = env_vars {
            cmd.envs(vars);
        }

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
