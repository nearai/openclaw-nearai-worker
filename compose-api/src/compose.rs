use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ApiError;
use crate::store::Instance;

/// Default NEAR AI Cloud API URL used when not specified per-instance.
pub const DEFAULT_NEARAI_API_URL: &str = "https://cloud-api.near.ai/v1";

pub struct ContainerHealth {
    pub state: String,
    pub health: String,
}

pub struct InstanceConfig<'a> {
    pub name: &'a str,
    pub nearai_api_key: &'a str,
    pub token: &'a str,
    pub gateway_port: u16,
    pub ssh_port: u16,
    pub ssh_pubkey: &'a str,
    pub image: &'a str,
    pub nearai_api_url: &'a str,
    pub service_type: &'a str,
    pub bastion_ssh_pubkey: Option<&'a str>,
    /// Memory limit (e.g. "1g", "2g"). Omit to use compose template default.
    pub mem_limit: Option<&'a str>,
    /// CPU limit (e.g. "2", "4"). Omit to use compose template default.
    pub cpus: Option<&'a str>,
    /// Container storage limit (e.g. "10G", "20G"). Omit to use compose template default.
    pub storage_size: Option<&'a str>,
}

/// Manages one Docker Compose project per worker via the `docker compose` CLI.
pub struct ComposeManager {
    /// Compose templates keyed by service type ("openclaw", "ironclaw", etc.).
    compose_files: HashMap<String, PathBuf>,
    /// Directory where per-instance .env files are written (e.g. data/envs/).
    env_dir: PathBuf,
    /// SSH public key of the bastion host (injected into worker authorized_keys).
    bastion_ssh_pubkey: Option<String>,
}

impl ComposeManager {
    pub fn new(
        compose_files: HashMap<String, PathBuf>,
        env_dir: PathBuf,
        bastion_ssh_pubkey: Option<String>,
    ) -> Result<Self, ApiError> {
        // Ensure the env directory exists
        std::fs::create_dir_all(&env_dir)
            .map_err(|e| ApiError::Internal(format!("Failed to create env dir: {}", e)))?;

        // Validate that compose files exist
        for (name, path) in &compose_files {
            if !path.exists() {
                return Err(ApiError::Internal(format!(
                    "Compose file not found for '{}': {}",
                    name,
                    path.display()
                )));
            }
        }

        if !compose_files.contains_key("openclaw") {
            return Err(ApiError::Internal(
                "Default 'openclaw' compose file must be provided".to_string(),
            ));
        }

        Ok(Self {
            compose_files,
            env_dir,
            bastion_ssh_pubkey,
        })
    }

    /// Resolve the compose file for a given service type, falling back to openclaw.
    fn compose_file_for(&self, service_type: Option<&str>) -> &Path {
        service_type
            .and_then(|st| self.compose_files.get(st))
            .or_else(|| self.compose_files.get("openclaw"))
            .expect("default compose file must exist")
    }

    fn env_path(&self, name: &str) -> PathBuf {
        self.env_dir.join(format!("{}.env", name))
    }

    // ── env-file helpers ──────────────────────────────────────────────

    /// Write a per-instance .env file consumed by docker-compose.worker.yml.
    /// Rejects keys/values containing newlines to prevent injection of arbitrary env vars.
    pub fn write_env_file(
        &self,
        name: &str,
        vars: &HashMap<String, String>,
    ) -> Result<PathBuf, ApiError> {
        for (k, v) in vars {
            if k.contains('\n') || k.contains('\r') || v.contains('\n') || v.contains('\r') {
                return Err(ApiError::Internal(
                    "env file rejected: key or value contains newline (injection attempt?)"
                        .to_string(),
                ));
            }
        }
        let path = self.env_path(name);
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
        let path = self.env_path(name);
        let _ = std::fs::remove_file(path);
    }

    // ── compose lifecycle ─────────────────────────────────────────────

    /// `docker compose -p openclaw-{name} up -d --pull always`
    pub fn up(&self, cfg: &InstanceConfig) -> Result<(), ApiError> {
        let mut vars = HashMap::new();
        vars.insert("NEARAI_API_KEY".into(), cfg.nearai_api_key.into());
        vars.insert("NEARAI_API_URL".into(), cfg.nearai_api_url.into());
        vars.insert("OPENCLAW_GATEWAY_TOKEN".into(), cfg.token.into());
        vars.insert("GATEWAY_PORT".into(), cfg.gateway_port.to_string());
        vars.insert("SSH_PORT".into(), cfg.ssh_port.to_string());
        vars.insert("OPENCLAW_IMAGE".into(), cfg.image.to_string());
        vars.insert("SSH_PUBKEY".into(), cfg.ssh_pubkey.into());
        if let Some(bastion_key) = cfg.bastion_ssh_pubkey {
            vars.insert("BASTION_SSH_PUBKEY".into(), bastion_key.into());
        }
        vars.insert("SERVICE_TYPE".into(), cfg.service_type.to_string());
        if let Some(v) = cfg.mem_limit {
            vars.insert("MEM_LIMIT".into(), v.into());
        }
        if let Some(v) = cfg.cpus {
            vars.insert("CPUS".into(), v.into());
        }
        if let Some(v) = cfg.storage_size {
            vars.insert("STORAGE_SIZE".into(), v.into());
        }
        let env_path = self.write_env_file(cfg.name, &vars)?;

        // Pull from registry for remote images (contain '/') or digest-pinned references;
        // local-only images (no '/') use --pull never
        let pull_policy = if cfg.image.contains('/') || cfg.image.contains("@sha256:") {
            "always"
        } else {
            "never"
        };
        self.compose_cmd(
            cfg.name,
            &env_path,
            &["up", "-d", "--pull", pull_policy],
            Some(&vars),
            Some(cfg.service_type),
        )
    }

    /// `docker compose -p openclaw-{name} down -v` (removes volumes too)
    pub fn down(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let env_path = self.env_path(name);
        self.compose_cmd(name, &env_path, &["down", "-v"], None, service_type)?;
        self.remove_env_file(name);
        Ok(())
    }

    pub fn stop(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let env_path = self.env_path(name);
        self.compose_cmd(name, &env_path, &["stop"], None, service_type)
    }

    pub fn start(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let env_path = self.env_path(name);
        self.compose_cmd(name, &env_path, &["start"], None, service_type)
    }

    pub fn restart(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let env_path = self.env_path(name);
        self.compose_cmd(name, &env_path, &["restart"], None, service_type)
    }

    /// Returns the output of `docker compose ps --format json`.
    pub fn status(&self, name: &str, service_type: Option<&str>) -> Result<String, ApiError> {
        let env_path = self.env_path(name);
        let project = format!("openclaw-{}", name);
        let compose_file = self.compose_file_for(service_type);

        let output = Command::new("docker")
            .args([
                "compose",
                "-p",
                &project,
                "-f",
                compose_file.to_str().unwrap(),
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

    /// Fetch the status of all managed gateway containers in a single `docker ps` call.
    /// Returns a map from instance name to container state (e.g. "running", "exited").
    /// Retries up to 3 times on transient failures before returning an error.
    pub fn all_statuses(&self) -> Result<HashMap<String, String>, ApiError> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();

        for attempt in 1..=MAX_ATTEMPTS {
            match self.docker_ps_statuses() {
                Ok(map) => return Ok(map),
                Err(e) => {
                    last_err = e.to_string();
                    tracing::warn!(
                        "docker ps failed (attempt {}/{}): {}",
                        attempt,
                        MAX_ATTEMPTS,
                        last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        }

        Err(ApiError::Internal(format!(
            "docker ps failed after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )))
    }

    fn docker_ps_statuses(&self) -> Result<HashMap<String, String>, ApiError> {
        let output = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                "label=openclaw.managed=true",
                "--format",
                "{{.Names}}\t{{.State}}",
            ])
            .output()
            .map_err(|e| ApiError::Internal(format!("failed to run docker ps: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!("docker ps failed: {stderr}")));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let map = stdout
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                let (container_name, state) = line.split_once('\t')?;
                // Match pattern: openclaw-{name}-gateway-1
                let name = container_name
                    .strip_prefix("openclaw-")
                    .and_then(|s| s.strip_suffix("-gateway-1"))?;
                if !crate::is_valid_instance_name(name) {
                    tracing::warn!("skipping container with invalid instance name: {}", name);
                    return None;
                }
                Some((name.to_string(), state.to_string()))
            })
            .collect();
        Ok(map)
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

    /// Export both the config volume and workspace volume from an instance's
    /// gateway container as a single tar archive.
    /// Uses `docker exec tar` to capture both directories relative to `/home/agent/`.
    pub fn export_instance_data(
        &self,
        name: &str,
        service_type: Option<&str>,
    ) -> Result<Vec<u8>, ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);
        let (config_dir, workspace_dir) = match service_type {
            Some("ironclaw") => (".ironclaw", "workspace"),
            _ => (".openclaw", "openclaw"),
        };
        let output = Command::new("docker")
            .args([
                "exec",
                &container,
                "tar",
                "cf",
                "-",
                "-C",
                "/home/agent",
                config_dir,
                workspace_dir,
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
                Some(n) if crate::is_valid_instance_name(n) => n.to_string(),
                Some(n) => {
                    tracing::warn!("skipping instance with invalid name: {}", n);
                    continue;
                }
                None => {
                    tracing::debug!("skipping non-gateway container: {}", container_name);
                    continue;
                }
            };

            match self.inspect_container(&name, container_name) {
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
    fn inspect_container(&self, name: &str, container_name: &str) -> Result<Instance, ApiError> {
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
        let nearai_api_url = env_map
            .get("NEARAI_API_URL")
            .cloned()
            .filter(|s| !s.is_empty());
        let image_env = env_map.get("OPENCLAW_IMAGE").cloned();
        // Resolve service_type: label (most reliable) → container env → persisted .env file
        let service_type = v
            .pointer("/Config/Labels/openclaw.service_type")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                env_map
                    .get("SERVICE_TYPE")
                    .cloned()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| self.read_service_type_from_env_file(name));

        if service_type.is_none() {
            tracing::warn!(
                "Instance '{}' has no SERVICE_TYPE in labels, container env, or env file. \
                 Upgrade operations will fail until this is resolved.",
                name
            );
        }

        // Parse port bindings from .HostConfig.PortBindings
        let port_bindings = v.pointer("/HostConfig/PortBindings");
        let gateway_port =
            Self::extract_host_port(port_bindings, "18789/tcp").ok_or_else(|| {
                ApiError::Internal(format!("missing gateway port binding for {}", name))
            })?;
        let ssh_port = Self::extract_host_port(port_bindings, "2222/tcp")
            .ok_or_else(|| ApiError::Internal(format!("missing ssh port binding for {}", name)))?;

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
        let image_digest = self.resolve_image_digest(name);

        Ok(Instance {
            name: name.to_string(),
            token,
            gateway_port,
            ssh_port,
            created_at,
            ssh_pubkey,
            nearai_api_key,
            nearai_api_url,
            active,
            image,
            image_digest,
            service_type,
            mem_limit: None,
            cpus: None,
            storage_size: None,
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
        vars.insert(
            "NEARAI_API_URL".into(),
            inst.nearai_api_url
                .as_deref()
                .unwrap_or(DEFAULT_NEARAI_API_URL)
                .to_string(),
        );
        vars.insert("OPENCLAW_GATEWAY_TOKEN".into(), inst.token.clone());
        vars.insert("GATEWAY_PORT".into(), inst.gateway_port.to_string());
        vars.insert("SSH_PORT".into(), inst.ssh_port.to_string());
        vars.insert("SSH_PUBKEY".into(), inst.ssh_pubkey.clone());
        if let Some(ref bastion_key) = self.bastion_ssh_pubkey {
            vars.insert("BASTION_SSH_PUBKEY".into(), bastion_key.clone());
        }
        if let Some(ref image) = inst.image {
            vars.insert("OPENCLAW_IMAGE".into(), image.clone());
        }
        vars.insert(
            "SERVICE_TYPE".into(),
            inst.service_type
                .clone()
                .unwrap_or_else(|| "openclaw".to_string()),
        );
        self.write_env_file(&inst.name, &vars)
    }

    /// Read SERVICE_TYPE from the persisted .env file for an instance.
    /// Fallback for containers created before SERVICE_TYPE was added to the
    /// compose template environment block.
    fn read_service_type_from_env_file(&self, name: &str) -> Option<String> {
        let path = self.env_path(name);
        let content = std::fs::read_to_string(&path).ok()?;
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("SERVICE_TYPE=") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    // ── internal ──────────────────────────────────────────────────────

    fn compose_cmd(
        &self,
        name: &str,
        env_path: &Path,
        args: &[&str],
        env_vars: Option<&HashMap<String, String>>,
        service_type: Option<&str>,
    ) -> Result<(), ApiError> {
        let project = format!("openclaw-{}", name);
        let compose_file = self.compose_file_for(service_type);

        let mut cmd = Command::new("docker");
        cmd.args([
            "compose",
            "-p",
            &project,
            "-f",
            compose_file.to_str().unwrap(),
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
