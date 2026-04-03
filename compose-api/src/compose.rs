use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::ApiError;
use crate::store::Instance;

/// Default NEAR AI Cloud API URL used when not specified per-instance.
pub const DEFAULT_NEARAI_API_URL: &str = "https://cloud-api.near.ai/v1";

fn derive_nearai_mcp_url(api_url: &str) -> String {
    let base = api_url.trim_end_matches('/');
    let base = base.strip_suffix("/v1").unwrap_or(base);
    format!("{}/mcp", base)
}

/// Insert OAuth-related env vars into the given map.
/// Shared by `up()` and `ensure_env_file()` to avoid duplication.
fn insert_oauth_env_vars(
    vars: &mut HashMap<String, String>,
    instance_name: &str,
    openclaw_domain: Option<&str>,
    google_oauth_client_id: Option<&str>,
    oauth_exchange_url: Option<&str>,
) {
    if let Some(domain) = openclaw_domain {
        vars.insert("OPENCLAW_DOMAIN".into(), domain.into());
        vars.insert("OPENCLAW_INSTANCE_NAME".into(), instance_name.into());
    }
    if let Some(client_id) = google_oauth_client_id {
        vars.insert("GOOGLE_OAUTH_CLIENT_ID".into(), client_id.into());
    }
    if let Some(url) = oauth_exchange_url {
        vars.insert("IRONCLAW_OAUTH_EXCHANGE_URL".into(), url.into());
    }
}

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
    /// Domain for multi-tenant deployment (e.g. "agent0.near.ai").
    /// When set, configures the OAuth auth proxy callback URL in the container.
    pub openclaw_domain: Option<&'a str>,
    /// Google OAuth client ID (public, not secret) for constructing auth URLs.
    pub google_oauth_client_id: Option<&'a str>,
    /// URL of the platform's OAuth token exchange proxy.
    pub oauth_exchange_url: Option<&'a str>,
    /// Additional environment variables.
    pub extra_env: Option<&'a std::collections::HashMap<String, String>>,
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

    /// Infer service type from image name: "ironclaw" if image contains "ironclaw", otherwise
    /// "openclaw". Does not depend on which compose files are currently loaded.
    pub fn infer_service_type_from_image(&self, image: Option<&str>) -> &'static str {
        let img_lower = image.unwrap_or("").to_lowercase();
        if img_lower.contains("ironclaw") {
            "ironclaw"
        } else {
            "openclaw"
        }
    }

    /// Resolve the compose file for a given service type, falling back to openclaw.
    fn compose_file_for(&self, service_type: Option<&str>) -> &Path {
        service_type
            .and_then(|st| self.compose_files.get(st))
            .or_else(|| self.compose_files.get("openclaw"))
            .expect("default compose file must exist")
    }

    pub fn env_dir(&self) -> &Path {
        &self.env_dir
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

    /// Read all key=value pairs from an instance .env file into a HashMap.
    /// Used by `start()` to pass env vars explicitly to docker compose,
    /// overriding CVM-level process env (which always has OPENCLAW_IMAGE
    /// set to the openclaw image, even for ironclaw instances).
    fn read_env_file_vars(&self, path: &Path) -> HashMap<String, String> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };
        content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let (key, value) = line.split_once('=')?;
                Some((key.to_string(), value.to_string()))
            })
            .collect()
    }

    /// Recover an instance from its persisted .env file.
    /// Returns the reconstructed Instance if the .env file exists and has
    /// the required fields. Fails if critical fields (token, API key,
    /// SSH pubkey, ports) are missing or empty.
    pub fn recover_from_env(&self, name: &str) -> Result<Instance, ApiError> {
        if !crate::is_valid_instance_name(name) {
            return Err(ApiError::BadRequest(format!(
                "Invalid instance name: '{}'",
                name
            )));
        }
        let env_path = self.env_path(name);
        if !env_path.exists() {
            return Err(ApiError::NotFound(format!(
                "No .env file found for instance '{}'",
                name
            )));
        }
        // Verify both Docker volumes exist (user data)
        for suffix in &["config", "workspace"] {
            let vol = format!("openclaw-{}_{}", name, suffix);
            let check = Command::new("docker")
                .args(["volume", "inspect", &vol])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap_or_else(|_| std::process::ExitStatus::default());
            if !check.success() {
                return Err(ApiError::BadRequest(format!(
                    "Docker volume '{}' not found — cannot recover without user data",
                    vol
                )));
            }
        }
        let vars = self.read_env_file_vars(&env_path);

        // Required fields — fail recovery if missing/empty
        let gateway_port: u16 = vars
            .get("GATEWAY_PORT")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| {
                ApiError::BadRequest(format!("GATEWAY_PORT missing or invalid in {}.env", name))
            })?;
        let ssh_port: u16 = vars
            .get("SSH_PORT")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| {
                ApiError::BadRequest(format!("SSH_PORT missing or invalid in {}.env", name))
            })?;
        let token = vars
            .get("OPENCLAW_GATEWAY_TOKEN")
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "OPENCLAW_GATEWAY_TOKEN missing or empty in {}.env",
                    name
                ))
            })?;
        let nearai_api_key = vars
            .get("NEARAI_API_KEY")
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| {
                ApiError::BadRequest(format!("NEARAI_API_KEY missing or empty in {}.env", name))
            })?;
        let ssh_pubkey = vars
            .get("SSH_PUBKEY")
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| {
                ApiError::BadRequest(format!("SSH_PUBKEY missing or empty in {}.env", name))
            })?;

        let nearai_api_url = vars.get("NEARAI_API_URL").cloned();
        let image = vars.get("OPENCLAW_IMAGE").cloned();

        // Infer service_type from env, falling back to image name
        let service_type = vars.get("SERVICE_TYPE").cloned().or_else(|| {
            Some(
                self.infer_service_type_from_image(image.as_deref())
                    .to_string(),
            )
        });

        // Collect extra env vars: anything not in the core set written by
        // ensure_env_file / up(). These include user-configured vars like
        // CHANNEL_RELAY_URL, CHANNEL_RELAY_API_KEY, etc.
        const CORE_KEYS: &[&str] = &[
            "NEARAI_API_KEY",
            "NEARAI_API_URL",
            "OPENCLAW_GATEWAY_TOKEN",
            "GATEWAY_PORT",
            "SSH_PORT",
            "SSH_PUBKEY",
            "BASTION_SSH_PUBKEY",
            "OPENCLAW_IMAGE",
            "SERVICE_TYPE",
            "WORKER_NETWORK",
            "MEM_LIMIT",
            "CPUS",
            "STORAGE_SIZE",
            // OAuth vars written by insert_oauth_env_vars
            "OPENCLAW_DOMAIN",
            "OPENCLAW_INSTANCE_NAME",
            "GOOGLE_OAUTH_CLIENT_ID",
            "IRONCLAW_OAUTH_EXCHANGE_URL",
        ];
        let extra: HashMap<String, String> = vars
            .iter()
            .filter(|(k, _)| !CORE_KEYS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let extra_env = if extra.is_empty() { None } else { Some(extra) };

        Ok(Instance {
            name: name.to_string(),
            token,
            gateway_port,
            ssh_port,
            created_at: chrono::Utc::now(),
            ssh_pubkey,
            nearai_api_key,
            nearai_api_url,
            active: false,
            image,
            image_digest: None,
            service_type,
            mem_limit: vars.get("MEM_LIMIT").cloned(),
            cpus: vars.get("CPUS").cloned(),
            storage_size: vars.get("STORAGE_SIZE").cloned(),
            extra_env,
        })
    }

    // ── network helpers ───────────────────────────────────────────────

    /// Return the persistent network name for an instance.
    fn network_name(instance_name: &str) -> String {
        format!("openclaw-net-{}", instance_name)
    }

    /// Ensure a per-instance Docker network exists.
    /// Pre-creating the network as `external: true` in the compose template
    /// prevents Docker Compose from tearing it down on container restart,
    /// avoiding bridge/veth churn that can trigger kernel ZFS/RCU stalls.
    fn ensure_network(instance_name: &str) -> Result<(), ApiError> {
        let net = Self::network_name(instance_name);
        // `docker network create` is idempotent-ish: returns an error if the
        // network already exists, which we ignore.
        let output = Command::new("docker")
            .args(["network", "create", "--driver", "bridge", &net])
            .output()
            .map_err(|e| ApiError::Internal(format!("docker network create: {}", e)))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("already exists") {
                return Err(ApiError::Internal(format!(
                    "docker network create failed: {}",
                    stderr
                )));
            }
        }
        Ok(())
    }

    /// Remove the per-instance Docker network (best-effort, ignore errors).
    fn remove_network(instance_name: &str) {
        let net = Self::network_name(instance_name);
        let _ = docker_command().args(["network", "rm", &net]).output();
    }

    // ── compose lifecycle ─────────────────────────────────────────────

    pub fn up(&self, cfg: &InstanceConfig) -> Result<(), ApiError> {
        Self::ensure_network(cfg.name)?;
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
        vars.insert("WORKER_NETWORK".into(), Self::network_name(cfg.name));
        if let Some(v) = cfg.mem_limit {
            vars.insert("MEM_LIMIT".into(), v.into());
        }
        if let Some(v) = cfg.cpus {
            vars.insert("CPUS".into(), v.into());
        }
        if let Some(v) = cfg.storage_size {
            vars.insert("STORAGE_SIZE".into(), v.into());
        }
        insert_oauth_env_vars(
            &mut vars,
            cfg.name,
            cfg.openclaw_domain,
            cfg.google_oauth_client_id,
            cfg.oauth_exchange_url,
        );
        if let Some(extra) = cfg.extra_env {
            for (k, v) in extra {
                vars.insert(k.clone(), v.clone());
            }
        }
        if cfg.service_type == "ironclaw" {
            vars.insert(
                "NEARAI_MCP_URL".into(),
                derive_nearai_mcp_url(cfg.nearai_api_url),
            );
            vars.insert("NEARAI_MCP_API_KEY".into(), cfg.nearai_api_key.into());
        }
        let env_path = self.write_env_file(cfg.name, &vars)?;

        // Pull remote images via `docker pull` (compose v5 --pull is broken on ZFS).
        // Skip if already cached to avoid unnecessary registry round-trips / rate limits.
        let is_remote = cfg.image.contains('/') || cfg.image.contains("@sha256:");
        if is_remote {
            let check = Command::new("docker")
                .args(["image", "inspect", cfg.image])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap_or_else(|_| std::process::ExitStatus::default());
            if !check.success() {
                let output = Command::new("docker")
                    .args(["pull", cfg.image])
                    .output()
                    .map_err(|e| ApiError::Internal(format!("docker pull: {}", e)))?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(ApiError::Internal(format!(
                        "docker pull failed: {}",
                        stderr
                    )));
                }
            }
        }
        self.compose_cmd(
            cfg.name,
            &env_path,
            &["up", "-d", "--pull", "never"],
            Some(&vars),
            Some(cfg.service_type),
        )?;

        // Clean up dangling images left behind by upgrades.
        let _ = Command::new("docker")
            .args(["image", "prune", "-f"])
            .output();

        Ok(())
    }

    /// `docker compose -p openclaw-{name} down -v` (removes volumes too)
    pub fn down(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let env_path = self.env_path(name);
        self.compose_cmd(name, &env_path, &["down", "-v"], None, service_type)?;
        self.remove_env_file(name);
        Self::remove_network(name);
        Ok(())
    }

    pub fn stop(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let env_path = self.env_path(name);
        self.compose_cmd(name, &env_path, &["stop"], None, service_type)
    }

    pub fn start(
        &self,
        name: &str,
        force_recreate: bool,
        service_type: Option<&str>,
    ) -> Result<(), ApiError> {
        Self::ensure_network(name)?;
        let env_path = self.env_path(name);
        // Read OPENCLAW_IMAGE from the instance .env file and pass it
        // explicitly so it overrides the CVM-level process env (which is
        // always the openclaw image, even for ironclaw instances).
        let env_vars = self.read_env_file_vars(&env_path);
        // Use `up -d` instead of `start` so the container is recreated with
        // the current network config. A plain `start` reuses the stopped
        // container's stored network ID, which fails if the network was
        // deleted (e.g. after CVM reboot cleanup).
        let mut args = vec!["up", "-d", "--pull", "never"];
        if force_recreate {
            args.push("--force-recreate");
        }
        self.compose_cmd(name, &env_path, &args, Some(&env_vars), service_type)
    }

    pub fn restart(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        self.start(name, true, service_type)
    }

    /// Delete an orphaned instance even if its `.env` file is missing.
    /// When the env file exists we try the normal compose-managed teardown first;
    /// otherwise we fall back to removing known container/volumes/network by name.
    pub fn cleanup_orphan(&self, name: &str, service_type: Option<&str>) -> Result<(), ApiError> {
        let env_path = self.env_path(name);
        if env_path.exists() {
            match self.down(name, service_type) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(
                        "compose down failed for orphan '{}', falling back to direct cleanup: {}",
                        name,
                        e
                    );
                }
            }
        }

        self.remove_named_artifact(
            "container",
            &["rm", "-f", &format!("openclaw-{}-gateway-1", name)],
        )?;
        self.remove_named_artifact(
            "volume",
            &["volume", "rm", "-f", &format!("openclaw-{}_config", name)],
        )?;
        self.remove_named_artifact(
            "volume",
            &[
                "volume",
                "rm",
                "-f",
                &format!("openclaw-{}_workspace", name),
            ],
        )?;
        self.remove_env_file(name);
        Self::remove_network(name);
        Ok(())
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

    /// Like `all_statuses()` but returns `(state, health)` per instance,
    /// so callers can distinguish "running but unhealthy" from "running and healthy".
    pub fn all_health_statuses(&self) -> Result<HashMap<String, ContainerHealth>, ApiError> {
        // Use {{.State}} and {{.Status}} — the latter contains health in
        // parentheses, e.g. "Up 5 minutes (healthy)". {{.Health}} is NOT a
        // valid Go template field in older Docker versions (causes error).
        let output = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                "label=openclaw.managed=true",
                "--format",
                "{{.Names}}\t{{.State}}\t{{.Status}}",
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
                let mut parts = line.splitn(3, '\t');
                let container_name = parts.next()?;
                let state = parts.next()?;
                let status_text = parts.next().unwrap_or("");
                let name = container_name
                    .strip_prefix("openclaw-")
                    .and_then(|s| s.strip_suffix("-gateway-1"))?;
                if !crate::is_valid_instance_name(name) {
                    return None;
                }
                // Parse health from status text: "Up 5 min (healthy)" → "healthy"
                let health = if let Some(start) = status_text.rfind('(') {
                    status_text[start + 1..].trim_end_matches(')').to_string()
                } else {
                    "none".to_string()
                };
                Some((
                    name.to_string(),
                    ContainerHealth {
                        state: state.to_string(),
                        health,
                    },
                ))
            })
            .collect();
        Ok(map)
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
    /// `service_type` must match the instance (ironclaw vs openclaw); if it is wrong,
    /// the wrong dirs are archived and restore will create the wrong paths in the new container.
    pub fn export_instance_data(
        &self,
        name: &str,
        service_type: Option<&str>,
    ) -> Result<Vec<u8>, ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);
        let (config_dir, workspace_dir) = match service_type {
            Some("ironclaw") => (".ironclaw", "workspace"),
            Some("openclaw") => (".openclaw", "openclaw"),
            None => {
                return Err(ApiError::Internal(format!(
                    "Cannot export instance '{}': service_type is unknown (set SERVICE_TYPE in .env or recreate with correct type)",
                    name
                )));
            }
            Some(other) => {
                return Err(ApiError::Internal(format!(
                    "Unknown service_type for export: '{}' (instance '{}')",
                    other, name
                )));
            }
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
            // Fresh instances may not have workspace/config dirs yet — treat as empty export.
            // Both GNU tar and BusyBox tar emit "Cannot stat" / "No such file or directory"
            // when a source path doesn't exist.
            let is_missing_dir =
                stderr.contains("Cannot stat") || stderr.contains("No such file or directory");
            let is_docker_error = stderr.contains("No such container")
                || stderr.contains("is not running")
                || stderr.contains("Error response from daemon");
            if is_docker_error || (!is_missing_dir) {
                return Err(ApiError::Internal(format!(
                    "docker exec tar failed: {}",
                    stderr
                )));
            }
            tracing::warn!(
                "tar export: workspace/config dirs not found (fresh instance), treating as empty: {}",
                stderr.trim()
            );
        }

        Ok(output.stdout)
    }

    /// Import workspace and config data into an instance's gateway container.
    /// Extracts the given tar archive (same format as export_instance_data) into /home/agent.
    pub fn import_instance_data(&self, name: &str, tar_bytes: &[u8]) -> Result<(), ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);

        let mut child = Command::new("docker")
            .args([
                "exec",
                "-i",
                "-u",
                "agent",
                &container,
                "tar",
                "xf",
                "-",
                "-C",
                "/home/agent",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ApiError::Internal(format!("Failed to run docker exec: {}", e)))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| ApiError::Internal("Failed to get stdin".into()))?;
            stdin
                .write_all(tar_bytes)
                .map_err(|e| ApiError::Internal(format!("Failed to write tar to stdin: {}", e)))?;
            stdin
                .flush()
                .map_err(|e| ApiError::Internal(format!("Failed to flush stdin: {}", e)))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| ApiError::Internal(format!("Failed to wait for docker exec: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!(
                "docker exec tar extract failed: {}",
                stderr
            )));
        }

        Ok(())
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
        // Resolve service_type: label → container env → persisted .env file → infer from image.
        // Infer from image name so e.g. ironclaw-nearai-worker → ironclaw.
        let image_from_config = v
            .pointer("/Config/Image")
            .and_then(|i| i.as_str())
            .unwrap_or("");
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
            .or_else(|| self.read_service_type_from_env_file(name))
            .or_else(|| {
                let inferred = self.infer_service_type_from_image(Some(image_from_config));
                tracing::info!(
                    "Instance '{}': no SERVICE_TYPE in label/env/.env, inferring '{}' from image '{}'",
                    name,
                    inferred,
                    image_from_config
                );
                Some(inferred.to_string())
            });

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
            extra_env: None,
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
    /// `default_image` should be the correct image for this instance's service type
    /// (openclaw or ironclaw) — used when `inst.image` is None.
    pub fn ensure_env_file(
        &self,
        inst: &Instance,
        default_image: &str,
        openclaw_domain: Option<&str>,
        google_oauth_client_id: Option<&str>,
        oauth_exchange_url: Option<&str>,
    ) -> Result<PathBuf, ApiError> {
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
        // Resolve service_type first — needed to validate the image.
        // Prefer in-memory service_type, then existing .env value; only then default to openclaw.
        let service_type = inst
            .service_type
            .clone()
            .or_else(|| self.read_service_type_from_env_file(&inst.name))
            .unwrap_or_else(|| "openclaw".to_string());
        // Use the instance's stored image, but if it doesn't match the
        // service_type (e.g. openclaw image on an ironclaw instance after
        // a botched restart), fall back to the correct default.
        let image = match inst.image.as_deref() {
            Some(img) if service_type == "ironclaw" && !img.contains("ironclaw") => {
                tracing::warn!(
                    "Instance '{}': stored image '{}' doesn't match service_type 'ironclaw', using default",
                    inst.name, img
                );
                default_image
            }
            Some(img) if service_type != "ironclaw" && img.contains("ironclaw") => {
                tracing::warn!(
                    "Instance '{}': stored image '{}' doesn't match service_type '{}', using default",
                    inst.name, img, service_type
                );
                default_image
            }
            Some(img) => img,
            None => default_image,
        };
        vars.insert("OPENCLAW_IMAGE".into(), image.to_string());
        vars.insert("SERVICE_TYPE".into(), service_type.clone());
        vars.insert("WORKER_NETWORK".into(), Self::network_name(&inst.name));
        insert_oauth_env_vars(
            &mut vars,
            &inst.name,
            openclaw_domain,
            google_oauth_client_id,
            oauth_exchange_url,
        );
        if let Some(ref extra) = inst.extra_env {
            for (k, v) in extra {
                vars.insert(k.clone(), v.clone());
            }
        }
        if service_type == "ironclaw" {
            let nearai_api_url = inst
                .nearai_api_url
                .as_deref()
                .unwrap_or(DEFAULT_NEARAI_API_URL);
            vars.insert(
                "NEARAI_MCP_URL".into(),
                derive_nearai_mcp_url(nearai_api_url),
            );
            vars.insert("NEARAI_MCP_API_KEY".into(), inst.nearai_api_key.clone());
        }
        self.write_env_file(&inst.name, &vars)
    }

    /// Read SERVICE_TYPE from the persisted .env file for an instance.
    /// Fallback for containers created before SERVICE_TYPE was added to the
    /// compose template environment block.
    pub fn read_service_type_from_env_file(&self, name: &str) -> Option<String> {
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

        let mut cmd = docker_command();
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

    fn remove_named_artifact(&self, artifact: &str, args: &[&str]) -> Result<(), ApiError> {
        let output = docker_command().args(args).output().map_err(|e| {
            ApiError::Internal(format!("failed to run docker {} command: {}", artifact, e))
        })?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_lower = stderr.to_lowercase();
        let missing = stderr_lower.contains("no such")
            || stderr_lower.contains("not found")
            || stderr_lower.contains("no such container")
            || stderr_lower.contains("no such volume");
        if missing {
            return Ok(());
        }

        Err(ApiError::Internal(format!(
            "failed to remove {}: {}",
            artifact,
            stderr.trim()
        )))
    }
}

#[cfg(not(test))]
fn docker_command() -> Command {
    Command::new("docker")
}

#[cfg(test)]
fn docker_command() -> Command {
    if let Ok(path) = std::env::var("OPENCLAW_TEST_DOCKER_BIN") {
        Command::new(path)
    } else {
        Command::new("docker")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Utc;

    use super::*;

    #[test]
    fn test_derive_nearai_mcp_url_from_api_url() {
        assert_eq!(
            derive_nearai_mcp_url("https://cloud-api.near.ai/v1"),
            "https://cloud-api.near.ai/mcp"
        );
        assert_eq!(
            derive_nearai_mcp_url("https://cloud-api.near.ai/v1/"),
            "https://cloud-api.near.ai/mcp"
        );
        assert_eq!(
            derive_nearai_mcp_url("https://cloud-stg-api.near.ai"),
            "https://cloud-stg-api.near.ai/mcp"
        );
        assert_eq!(
            derive_nearai_mcp_url("https://cloud-stg-api.near.ai/"),
            "https://cloud-stg-api.near.ai/mcp"
        );
    }

    #[test]
    fn test_ensure_env_file_adds_nearai_mcp_env_for_ironclaw() {
        let temp = tempfile::tempdir().expect("temp dir");
        let openclaw_compose = temp.path().join("docker-compose.worker.yml");
        let ironclaw_compose = temp.path().join("docker-compose.ironclaw.yml");
        std::fs::write(&openclaw_compose, "services: {}\n").expect("write compose");
        std::fs::write(&ironclaw_compose, "services: {}\n").expect("write compose");

        let mut compose_files = HashMap::new();
        compose_files.insert("openclaw".to_string(), openclaw_compose);
        compose_files.insert("ironclaw".to_string(), ironclaw_compose);

        let manager = ComposeManager::new(compose_files, temp.path().join("envs"), None)
            .expect("compose manager");

        let instance = Instance {
            name: "alice".to_string(),
            token: "tok".to_string(),
            gateway_port: 19001,
            ssh_port: 19002,
            created_at: Utc::now(),
            ssh_pubkey: "ssh-ed25519 AAAA test".to_string(),
            nearai_api_key: "sk-user".to_string(),
            nearai_api_url: Some("https://cloud-stg-api.near.ai/v1".to_string()),
            active: true,
            image: Some("ironclaw-nearai-worker:test".to_string()),
            image_digest: None,
            service_type: Some("ironclaw".to_string()),
            mem_limit: None,
            cpus: None,
            storage_size: None,
            extra_env: None,
        };

        let env_path = manager
            .ensure_env_file(&instance, "ironclaw-nearai-worker:test", None, None, None)
            .expect("ensure env file");
        let env_content = std::fs::read_to_string(env_path).expect("read env file");

        assert!(env_content.contains("NEARAI_MCP_URL=https://cloud-stg-api.near.ai/mcp"));
        assert!(env_content.contains("NEARAI_MCP_API_KEY=sk-user"));
    }
}
