use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::ApiError;
use crate::store::Instance;

/// Default NEAR AI Cloud API URL used when not specified per-instance.
pub const DEFAULT_NEARAI_API_URL: &str = "https://cloud-api.near.ai/v1";

/// Env vars managed by compose-api (written by ensure_env_file / up).
/// Anything NOT in this list is considered user-supplied "extra_env".
const CORE_ENV_KEYS: &[&str] = &[
    "NEARAI_API_KEY",
    "NEARAI_API_URL",
    "OPENCLAW_GATEWAY_TOKEN",
    "GATEWAY_AUTH_TOKEN",
    "ENGINE_V2",
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
    "OPENCLAW_DOMAIN",
    "OPENCLAW_INSTANCE_NAME",
    "IRONCLAW_DOMAIN",
    "IRONCLAW_INSTANCE_NAME",
    "GOOGLE_OAUTH_CLIENT_ID",
    "IRONCLAW_OAUTH_EXCHANGE_URL",
];

/// System/Docker env vars to exclude when collecting extra_env from a container.
const SYSTEM_ENV_KEYS: &[&str] = &[
    "PATH", "HOME", "HOSTNAME", "LANG", "LC_ALL", "TERM", "SHLVL", "PWD", "OLDPWD", "USER", "SHELL",
];

/// Env keys compose-api owns: the ones it writes itself, plus the master key it resolves
/// from the container. `ensure_env_file` applies `extra_env` after everything else, so an
/// extra_env entry for one of these silently replaces the managed value — which is why
/// callers accepting an extra_env patch must refuse them.
pub fn is_managed_env_key(key: &str) -> bool {
    CORE_ENV_KEYS.contains(&key) || SYSTEM_ENV_KEYS.contains(&key) || key == "SECRETS_MASTER_KEY"
}

/// Where ironclaw's entrypoint persists the secrets master key, on the config volume.
const MASTER_KEY_PATH: &str = "/home/agent/.ironclaw/.master_key";

/// The places an instance's SECRETS_MASTER_KEY can be read from, cheapest first.
/// `docker cp` reads the config volume whether or not the container runs — verified
/// against a stopped container and one that was never started — so it covers the
/// stopped case that `docker exec` cannot. exec stays as the fallback.
#[derive(Clone, Copy)]
enum MasterKeySource {
    EnvFile,
    Copy,
    Exec,
}

impl MasterKeySource {
    fn label(self) -> &'static str {
        match self {
            Self::EnvFile => "instance .env",
            Self::Copy => "docker cp",
            Self::Exec => "docker exec",
        }
    }
}

/// True when the instance runs ironclaw, by either signal. The two disagree on
/// instances whose stored SERVICE_TYPE is openclaw while the image is ironclaw, and
/// those still hold an ironclaw master key.
pub fn is_ironclaw(service_type: Option<&str>, image: Option<&str>) -> bool {
    service_type == Some("ironclaw") || image.is_some_and(|i| i.contains("ironclaw"))
}

/// Both type signals and whether they agree, as one phrase — a master-key log line
/// has to be readable without cross-referencing the instance anywhere else.
pub fn type_signals(service_type: Option<&str>, image: Option<&str>) -> String {
    let image_says = match image {
        Some(i) if i.contains("ironclaw") => "ironclaw",
        Some(i) if i.contains("openclaw") => "openclaw",
        Some(_) => "unrecognized",
        None => "none",
    };
    let stored = service_type.unwrap_or("none");
    let verdict = if stored == image_says {
        "agree"
    } else {
        "disagree"
    };
    format!(
        "service_type={} image_says={} ({})",
        stored, image_says, verdict
    )
}

/// A master key is 64 hex chars (32 bytes). Anything else is a miss with a reason.
fn valid_master_key(raw: &str) -> Result<String, String> {
    let key = raw.trim();
    if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(key.to_string())
    } else {
        Err(format!("not valid 64-char hex (len={})", key.len()))
    }
}

fn docker_stderr(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text.trim().lines().next().unwrap_or("").trim().to_string();
    if line.is_empty() {
        "docker command failed".to_string()
    } else {
        line
    }
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
        vars.insert("IRONCLAW_DOMAIN".into(), domain.into());
        vars.insert("IRONCLAW_INSTANCE_NAME".into(), instance_name.into());
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
        if image.unwrap_or("").to_lowercase().contains("ironclaw") {
            "ironclaw"
        } else {
            "openclaw"
        }
    }

    /// Service type the image name states outright, or `None` when it names neither product —
    /// or, ambiguously, both. Unlike [`Self::infer_service_type_from_image`] this never guesses,
    /// so callers can use it as evidence rather than as a default.
    pub fn service_type_named_by_image(&self, image: Option<&str>) -> Option<&'static str> {
        let img_lower = image.unwrap_or("").to_lowercase();
        match (
            img_lower.contains("ironclaw"),
            img_lower.contains("openclaw"),
        ) {
            (true, false) => Some("ironclaw"),
            (false, true) => Some("openclaw"),
            _ => None,
        }
    }

    /// Decide an instance's service_type from the signals its container carries.
    ///
    /// The image decides whenever it names a product, because it is what the container is
    /// actually running, and service_type only exists to pick the matching compose template
    /// and binary. The label, the container env and the .env file are all copies of an
    /// earlier resolution — a "openclaw" recorded against an ironclaw container is exactly
    /// what `ensure_env_file` turns into an image rewrite, so none of them may outrank the
    /// image. A container created from a bare image id names no product; there the recorded
    /// values are used, in their original order.
    fn resolve_service_type(
        &self,
        name: &str,
        label: Option<&str>,
        env_map: &HashMap<String, String>,
        image_from_config: &str,
    ) -> Option<String> {
        let recorded = label
            .map(|s| s.to_string())
            .or_else(|| {
                env_map
                    .get("SERVICE_TYPE")
                    .cloned()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| self.read_service_type_from_env_file(name));

        // `.Config.Image` echoes whatever the container was created from, so it is the direct
        // evidence; OPENCLAW_IMAGE covers the case where that was a bare image id.
        let named = self
            .service_type_named_by_image(Some(image_from_config))
            .or_else(|| {
                self.service_type_named_by_image(env_map.get("OPENCLAW_IMAGE").map(String::as_str))
            });

        if let Some(named) = named {
            if let Some(stale) = recorded.as_deref().filter(|r| *r != named) {
                tracing::warn!(
                    "Instance '{}': recorded service_type '{}' disagrees with the running \
                     image '{}'; using '{}' from the image",
                    name,
                    stale,
                    image_from_config,
                    named
                );
            }
            return Some(named.to_string());
        }

        // The image names no product — a container created from a bare image id.
        recorded.or_else(|| {
            let inferred = self.infer_service_type_from_image(Some(image_from_config));
            tracing::info!(
                "Instance '{}': no SERVICE_TYPE in label/env/.env, inferring '{}' from image '{}'",
                name,
                inferred,
                image_from_config
            );
            Some(inferred.to_string())
        })
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

        let extra: HashMap<String, String> = vars
            .iter()
            .filter(|(k, _)| !CORE_ENV_KEYS.contains(&k.as_str()))
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
        let output = docker_command()
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
        vars.insert("GATEWAY_AUTH_TOKEN".into(), cfg.token.into());
        vars.insert("ENGINE_V2".into(), "true".into());
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
    ///
    /// When `full_export` is true, tars ALL of `/home/agent/` instead of specific subdirs.
    /// This is used for migration to capture the complete home directory.
    pub fn export_instance_data(
        &self,
        name: &str,
        service_type: Option<&str>,
        full_export: bool,
    ) -> Result<Vec<u8>, ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);

        let mut args = vec!["exec", &container, "tar", "cf", "-", "-C", "/home/agent"];

        if full_export {
            // Export everything in /home/agent
            args.push(".");
        } else {
            let (config_dir, workspace_dir) = instance_data_dirs(name, service_type)?;
            args.push(config_dir);
            args.push(workspace_dir);
        }

        let output = Command::new("docker")
            .args(&args)
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

    /// Ensure the age binary is present at /tmp/age in an instance's gateway
    /// container. No-op if it's already there (the container persists across
    /// backups), otherwise streams it in via docker exec stdin — docker cp
    /// does not work reliably across storage drivers. Written to a PID-unique
    /// temp path then atomically renamed, so concurrent copies can't observe a
    /// partially-written binary.
    pub fn copy_age_to_container(&self, name: &str) -> Result<(), ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);

        // Skip the ~8MB stream if a usable binary is already in place.
        let present = docker_command()
            .args(["exec", &container, "test", "-x", "/tmp/age"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if present {
            return Ok(());
        }

        let age_path =
            std::env::var("AGE_BINARY_PATH").unwrap_or_else(|_| "/usr/local/bin/age".to_string());
        let age_bytes = std::fs::read(&age_path)
            .map_err(|e| ApiError::Internal(format!("read age binary {}: {}", age_path, e)))?;

        run_docker_exec_stdin(
            &[
                "exec",
                "-i",
                &container,
                "sh",
                "-c",
                "t=/tmp/.age.$$.tmp; cat > \"$t\" && chmod 0755 \"$t\" && mv \"$t\" /tmp/age",
            ],
            &age_bytes,
            "age copy to container",
        )
    }

    /// Run the full backup pipeline inside an instance's gateway container:
    /// tar+gzip to a temp file, age-encrypt, then curl PUT to a presigned S3 URL.
    /// No archive bytes ever flow through this process — peak memory here is O(1),
    /// unlike export_instance_data which buffers the whole tar in a Vec.
    ///
    /// `stdin_payload` carries the encryption recipients (see build_backup_script
    /// for the protocol) so they never appear in argv. The presigned URL is
    /// passed via the BACKUP_URL env var.
    pub fn backup_instance_in_container(
        &self,
        name: &str,
        service_type: Option<&str>,
        full_export: bool,
        backup_id: &str,
        upload_url: &str,
        stdin_payload: &str,
    ) -> Result<(), ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);

        // --ignore-failed-read: live containers mutate files mid-read and fresh
        // instances may lack workspace dirs; both downgrade to tar exit 1.
        let tar_args = if full_export {
            "--ignore-failed-read -C /home/agent .".to_string()
        } else {
            let (config_dir, workspace_dir) = instance_data_dirs(name, service_type)?;
            format!(
                "--ignore-failed-read -C /home/agent {} {}",
                config_dir, workspace_dir
            )
        };

        let script = build_backup_script(backup_id, &tar_args);
        run_docker_exec_stdin(
            &[
                "exec",
                "-i",
                "-e",
                &format!("BACKUP_URL={}", upload_url),
                &container,
                "sh",
                "-c",
                &script,
            ],
            stdin_payload.as_bytes(),
            "in-container backup",
        )
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
        let image_from_config = v
            .pointer("/Config/Image")
            .and_then(|i| i.as_str())
            .unwrap_or("");
        let label_service_type = v
            .pointer("/Config/Labels/openclaw.service_type")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty());
        let service_type =
            self.resolve_service_type(name, label_service_type, &env_map, image_from_config);

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

        let mut extra: HashMap<String, String> = env_map
            .iter()
            .filter(|(k, v)| {
                !v.is_empty()
                    && !CORE_ENV_KEYS.contains(&k.as_str())
                    && !SYSTEM_ENV_KEYS.contains(&k.as_str())
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // ironclaw generates SECRETS_MASTER_KEY at runtime (entrypoint.sh writes it to
        // .master_key on disk). It's not in Config.Env, so read it from the container.
        // Deliberately still one exec for one service_type: discovery walks every
        // container on the node and its duration is bounded by the updater's health
        // gate. Instances the label misses are resolved by GET /instances/{name},
        // which every migration calls first.
        if service_type.as_deref() == Some("ironclaw") && !extra.contains_key("SECRETS_MASTER_KEY")
        {
            if self
                .read_master_key_from_container(name, container_name)
                .map(|key| extra.insert("SECRETS_MASTER_KEY".to_string(), key))
                .is_none()
            {
                tracing::info!(
                    "Instance '{}': no SECRETS_MASTER_KEY at discovery ({})",
                    name,
                    type_signals(service_type.as_deref(), Some(image_from_config))
                );
            }
        } else if is_ironclaw(service_type.as_deref(), Some(image_from_config))
            && !extra.contains_key("SECRETS_MASTER_KEY")
        {
            // The label and the image disagree — the roster this prints is what the
            // last investigation needed a log export to reconstruct.
            tracing::info!(
                "Instance '{}': master key deferred to GET /instances/{} ({})",
                name,
                name,
                type_signals(service_type.as_deref(), Some(image_from_config))
            );
        }

        let extra_env = if extra.is_empty() { None } else { Some(extra) };

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
            extra_env,
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

    /// Read SECRETS_MASTER_KEY from a running container's persisted .master_key file.
    /// Discovery's single cheap attempt; `resolve_master_key` covers the rest.
    fn read_master_key_from_container(&self, name: &str, container_name: &str) -> Option<String> {
        self.read_master_key(MasterKeySource::Exec, name, container_name)
            .ok()
    }

    /// Resolve an instance's SECRETS_MASTER_KEY from every place the key can live.
    ///
    /// ironclaw writes the key to `.master_key` on the config volume, so it outlives a
    /// stopped container — but the exec used during discovery does not, which is why a
    /// stopped instance stayed unmigratable until someone started it and restarted
    /// compose-api. Every source logs why it came up empty: an instance that never had a
    /// key must not look like one whose key we failed to read.
    pub fn resolve_master_key(
        &self,
        name: &str,
        container_name: &str,
        service_type: Option<&str>,
        image: Option<&str>,
    ) -> Option<String> {
        let signals = type_signals(service_type, image);
        tracing::info!(
            "Instance '{}': resolving SECRETS_MASTER_KEY ({})",
            name,
            signals
        );
        let mut missed: Vec<String> = Vec::new();
        for source in [
            MasterKeySource::EnvFile,
            MasterKeySource::Copy,
            MasterKeySource::Exec,
        ] {
            match self.read_master_key(source, name, container_name) {
                Ok(key) => {
                    tracing::info!(
                        "Instance '{}': SECRETS_MASTER_KEY resolved from {} ({}); missed before it: {}",
                        name,
                        source.label(),
                        signals,
                        if missed.is_empty() { "none".to_string() } else { missed.join("; ") }
                    );
                    return Some(key);
                }
                Err(reason) => {
                    tracing::info!(
                        "Instance '{}': {} did not yield SECRETS_MASTER_KEY ({})",
                        name,
                        source.label(),
                        reason
                    );
                    missed.push(format!("{}: {}", source.label(), reason));
                }
            }
        }
        tracing::warn!(
            "Instance '{}': no SECRETS_MASTER_KEY anywhere ({}, image_ref={}); tried {}. \
             Expected when the instance runs openclaw, which has no ironclaw key.",
            name,
            signals,
            image.unwrap_or("none"),
            missed.join("; ")
        );
        None
    }

    /// One source of the resolution chain. `Err` carries the reason for the log.
    fn read_master_key(
        &self,
        source: MasterKeySource,
        name: &str,
        container_name: &str,
    ) -> Result<String, String> {
        match source {
            MasterKeySource::EnvFile => {
                let raw = self
                    .read_env_file_value(name, "SECRETS_MASTER_KEY")
                    .ok_or_else(|| "not in the instance .env".to_string())?;
                valid_master_key(&raw)
            }
            MasterKeySource::Copy => {
                let dest = std::env::temp_dir().join(format!("{}.master_key", container_name));
                let output = docker_command()
                    .args([
                        "cp",
                        &format!("{}:{}", container_name, MASTER_KEY_PATH),
                        &dest.to_string_lossy(),
                    ])
                    .output()
                    .map_err(|e| format!("docker cp failed to run: {}", e))?;
                let result = if output.status.success() {
                    std::fs::read_to_string(&dest)
                        .map_err(|e| format!("copied file unreadable: {}", e))
                        .and_then(|raw| valid_master_key(&raw))
                } else {
                    Err(docker_stderr(&output.stderr))
                };
                let _ = std::fs::remove_file(&dest);
                result
            }
            MasterKeySource::Exec => {
                let output = docker_command()
                    .args(["exec", container_name, "cat", MASTER_KEY_PATH])
                    .output()
                    .map_err(|e| format!("docker exec failed to run: {}", e))?;
                if !output.status.success() {
                    return Err(docker_stderr(&output.stderr));
                }
                valid_master_key(&String::from_utf8_lossy(&output.stdout))
            }
        }
    }

    /// Query the application version from a running container.
    /// Runs `ironclaw --version` (or `openclaw --version`) and parses the semver.
    pub fn query_app_version(
        &self,
        name: &str,
        service_type: Option<&str>,
    ) -> Result<String, ApiError> {
        let container = format!("openclaw-{}-gateway-1", name);
        let binary = match service_type {
            Some("ironclaw") => "ironclaw",
            _ => "openclaw",
        };

        let output = Command::new("docker")
            .args(["exec", &container, binary, "--version"])
            .output()
            .map_err(|e| {
                ApiError::Internal(format!(
                    "failed to run docker exec {} --version: {}",
                    binary, e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!(
                "{} --version failed: {}",
                binary,
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Output is typically "ironclaw 0.29.0" or "openclaw 2026.2.15"
        let version = stdout.split_whitespace().last().unwrap_or("").to_string();

        if version.is_empty() {
            return Err(ApiError::Internal(format!(
                "{} --version returned empty output",
                binary
            )));
        }

        Ok(version)
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
        vars.insert("GATEWAY_AUTH_TOKEN".into(), inst.token.clone());
        vars.insert("ENGINE_V2".into(), "true".into());
        vars.insert("GATEWAY_PORT".into(), inst.gateway_port.to_string());
        vars.insert("SSH_PORT".into(), inst.ssh_port.to_string());
        vars.insert("SSH_PUBKEY".into(), inst.ssh_pubkey.clone());
        if let Some(ref bastion_key) = self.bastion_ssh_pubkey {
            vars.insert("BASTION_SSH_PUBKEY".into(), bastion_key.clone());
        }
        // Resolve service_type first — needed to validate the image.
        // Prefer in-memory service_type, then what the image names, then the existing .env value;
        // only then default to openclaw. The image comes before the .env for the same reason as in
        // `inspect_container`, and the "openclaw" default is last because whatever wins here is
        // written back to the .env, where a guess would read as fact on every later resolution.
        let service_type = inst
            .service_type
            .clone()
            .or_else(|| {
                self.service_type_named_by_image(inst.image.as_deref())
                    .map(|s| s.to_string())
            })
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
        vars.insert("SERVICE_TYPE".into(), service_type);
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
        self.write_env_file(&inst.name, &vars)
    }

    /// Read SERVICE_TYPE from the persisted .env file for an instance.
    /// Fallback for containers created before SERVICE_TYPE was added to the
    /// compose template environment block.
    pub fn read_service_type_from_env_file(&self, name: &str) -> Option<String> {
        self.read_env_file_value(name, "SERVICE_TYPE")
    }

    /// Read one key out of an instance's persisted .env file.
    fn read_env_file_value(&self, name: &str, key: &str) -> Option<String> {
        let content = std::fs::read_to_string(self.env_path(name)).ok()?;
        let prefix = format!("{}=", key);
        for line in content.lines() {
            if let Some(value) = line.strip_prefix(&prefix) {
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

/// Resolve the (config_dir, workspace_dir) pair under /home/agent that holds
/// an instance's data, by service type.
fn instance_data_dirs(
    name: &str,
    service_type: Option<&str>,
) -> Result<(&'static str, &'static str), ApiError> {
    match service_type {
        Some("ironclaw") => Ok((".ironclaw", "workspace")),
        Some("openclaw") => Ok((".openclaw", "openclaw")),
        None => Err(ApiError::Internal(format!(
            "Cannot export instance '{}': service_type is unknown (set SERVICE_TYPE in .env or recreate with correct type)",
            name
        ))),
        Some(other) => Err(ApiError::Internal(format!(
            "Unknown service_type for export: '{}' (instance '{}')",
            other, name
        ))),
    }
}

/// Total wall-clock cap for the in-container S3 upload. Keeps curl from
/// hanging forever on a stalled connection — without it the docker exec (and
/// the host blocking thread waiting on it) could be pinned indefinitely, since
/// the outer tokio timeout stops awaiting but cannot kill the child.
const UPLOAD_CURL_MAX_SECS: u32 = 600;
const UPLOAD_CURL_CONNECT_SECS: u32 = 30;

/// Build the shell script that runs the backup pipeline inside a worker
/// container: tar+gzip to a temp file, age-encrypt, curl PUT to $BACKUP_URL.
///
/// stdin protocol: first line is an X25519 recipient ("age1...") or empty;
/// remaining lines are SSH pubkeys, written to a file for age -R. At least
/// one recipient is required (exit 3 otherwise). tar exit 1 ("file changed
/// as we read it" on live containers) is tolerated; >1 is fatal. Temp paths
/// embed the backup id (readability) plus the shell PID `$$` so concurrent
/// backups of the same instance can't collide, and a trap removes them on
/// every exit path.
fn build_backup_script(backup_id: &str, tar_args: &str) -> String {
    format!(
        r#"read -r AGE_RCPT
TAR=/tmp/backup-{id}-$$.tar.gz
RCPT=/tmp/age-r-{id}-$$
cat > "$RCPT"
RARG=""
if [ -n "$AGE_RCPT" ]; then RARG="-r $AGE_RCPT"; fi
RFLAG=""
if [ -s "$RCPT" ]; then RFLAG="-R $RCPT"; fi
if [ -z "$RARG$RFLAG" ]; then echo "no encryption recipients" >&2; exit 3; fi
trap 'rm -f "$TAR" "$TAR.age" "$RCPT"' EXIT
tar czf "$TAR" {tar_args}
rc=$?
if [ $rc -gt 1 ]; then echo "tar failed rc=$rc" >&2; exit $rc; fi
/tmp/age -e $RARG $RFLAG -o "$TAR.age" "$TAR" || exit 4
curl --fail --connect-timeout {connect} --max-time {maxt} -sS -T "$TAR.age" "$BACKUP_URL"
"#,
        id = backup_id,
        tar_args = tar_args,
        connect = UPLOAD_CURL_CONNECT_SECS,
        maxt = UPLOAD_CURL_MAX_SECS,
    )
}

/// Spawn a docker command with piped stdin, write `stdin_bytes`, and wait.
/// The write runs on a separate thread so a large payload (e.g. the ~8MB age
/// binary) can't deadlock against the child filling its stderr pipe while we
/// block on stdin. Dropping stdin when the writer thread ends signals EOF.
/// `context` labels error messages.
fn run_docker_exec_stdin(args: &[&str], stdin_bytes: &[u8], context: &str) -> Result<(), ApiError> {
    let mut child = docker_command()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ApiError::Internal(format!("docker exec spawn ({}): {}", context, e)))?;

    let mut stdin = child.stdin.take().expect("stdin piped");
    let payload = stdin_bytes.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&payload));

    let output = child
        .wait_with_output()
        .map_err(|e| ApiError::Internal(format!("docker exec wait ({}): {}", context, e)))?;

    // Surface a stdin write error only if the child didn't already fail with a
    // more specific message (a child that exits early closes the pipe, which
    // shows up here as a broken-pipe write error we'd rather not report).
    let write_result = writer
        .join()
        .map_err(|_| ApiError::Internal(format!("stdin writer panicked ({})", context)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::Internal(format!(
            "{} failed (exit {:?}): {}",
            context,
            output.status.code(),
            stderr.trim()
        )));
    }
    write_result.map_err(|e| ApiError::Internal(format!("write stdin ({}): {}", context, e)))?;
    Ok(())
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
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_valid_master_key_trims_and_rejects_malformed() {
        let key = "a".repeat(64);
        assert_eq!(valid_master_key(&format!("{}\n", key)).unwrap(), key);
        assert!(valid_master_key("deadbeef").is_err());
        assert!(valid_master_key(&"z".repeat(64)).is_err());
    }

    #[test]
    fn test_type_signals_names_both_sides_and_the_verdict() {
        assert_eq!(
            type_signals(
                Some("ironclaw"),
                Some("nearaidev/ironclaw-nearai-worker:1.2.0")
            ),
            "service_type=ironclaw image_says=ironclaw (agree)"
        );
        assert_eq!(
            type_signals(
                Some("openclaw"),
                Some("nearaidev/ironclaw-nearai-worker@sha256:abc")
            ),
            "service_type=openclaw image_says=ironclaw (disagree)"
        );
    }

    #[test]
    fn test_is_ironclaw_accepts_either_signal() {
        assert!(is_ironclaw(Some("ironclaw"), None));
        assert!(is_ironclaw(
            Some("openclaw"),
            Some("nearaidev/ironclaw-nearai-worker@sha256:abc")
        ));
        assert!(!is_ironclaw(
            Some("openclaw"),
            Some("nearaidev/openclaw-nearai-worker:latest")
        ));
        assert!(!is_ironclaw(None, None));
    }

    fn test_manager(dir: &Path) -> ComposeManager {
        let mut files = HashMap::new();
        for st in ["openclaw", "ironclaw"] {
            let path = dir.join(format!("{}.yml", st));
            std::fs::write(&path, "services: {}\n").unwrap();
            files.insert(st.to_string(), path);
        }
        ComposeManager::new(files, dir.join("envs"), None).unwrap()
    }

    fn test_instance(name: &str, image: Option<&str>, service_type: Option<&str>) -> Instance {
        Instance {
            name: name.to_string(),
            token: "t".into(),
            gateway_port: 18789,
            ssh_port: 2222,
            created_at: Utc::now(),
            ssh_pubkey: "ssh-ed25519 AAAA".into(),
            nearai_api_key: "k".into(),
            nearai_api_url: None,
            active: true,
            image: image.map(String::from),
            image_digest: None,
            service_type: service_type.map(String::from),
            mem_limit: None,
            cpus: None,
            storage_size: None,
            extra_env: None,
        }
    }

    const IRONCLAW_IMAGE: &str = "nearaidev/ironclaw-nearai-worker@sha256:46c302d3";
    const OPENCLAW_IMAGE: &str = "nearaidev/openclaw-nearai-worker:latest";

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The whole point of the change: whichever copy carries the stale "openclaw" — the
    /// label, the container env, or the .env file — the running image overrules it.
    #[test]
    fn test_resolve_service_type_prefers_the_image_over_every_recorded_copy() {
        let dir = tempfile::tempdir().unwrap();
        let m = test_manager(dir.path());
        std::fs::write(m.env_path("a"), "SERVICE_TYPE=openclaw\n").unwrap();

        // stale label
        assert_eq!(
            m.resolve_service_type("a", Some("openclaw"), &env_map(&[]), IRONCLAW_IMAGE),
            Some("ironclaw".into())
        );
        // stale container env
        assert_eq!(
            m.resolve_service_type(
                "a",
                None,
                &env_map(&[("SERVICE_TYPE", "openclaw")]),
                IRONCLAW_IMAGE
            ),
            Some("ironclaw".into())
        );
        // stale .env file only
        assert_eq!(
            m.resolve_service_type("a", None, &env_map(&[]), IRONCLAW_IMAGE),
            Some("ironclaw".into())
        );
    }

    #[test]
    fn test_resolve_service_type_falls_back_to_records_when_the_image_names_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let m = test_manager(dir.path());
        let bare_id = "sha256:e0e8b3cbfed68a90084781e2962f9c0deead51c5a3f11a488eef0283a4284bc2";

        // A container created from a bare image id carries no product name, so the label wins.
        assert_eq!(
            m.resolve_service_type("b", Some("ironclaw"), &env_map(&[]), bare_id),
            Some("ironclaw".into())
        );
        // …and OPENCLAW_IMAGE recovers the name when .Config.Image cannot.
        assert_eq!(
            m.resolve_service_type(
                "b",
                Some("openclaw"),
                &env_map(&[("OPENCLAW_IMAGE", IRONCLAW_IMAGE)]),
                bare_id
            ),
            Some("ironclaw".into())
        );
        // Nothing recorded and nothing named: the old guess remains.
        assert_eq!(
            m.resolve_service_type("b", None, &env_map(&[]), bare_id),
            Some("openclaw".into())
        );
    }

    #[test]
    fn test_resolve_service_type_keeps_agreeing_signals_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let m = test_manager(dir.path());
        assert_eq!(
            m.resolve_service_type("c", Some("openclaw"), &env_map(&[]), OPENCLAW_IMAGE),
            Some("openclaw".into())
        );
        assert_eq!(
            m.resolve_service_type("c", Some("ironclaw"), &env_map(&[]), IRONCLAW_IMAGE),
            Some("ironclaw".into())
        );
    }

    #[test]
    fn test_service_type_named_by_image_reports_unknown_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let m = test_manager(dir.path());
        assert_eq!(
            m.service_type_named_by_image(Some(IRONCLAW_IMAGE)),
            Some("ironclaw")
        );
        assert_eq!(
            m.service_type_named_by_image(Some(OPENCLAW_IMAGE)),
            Some("openclaw")
        );
        assert_eq!(m.service_type_named_by_image(Some("busybox:latest")), None);
        assert_eq!(m.service_type_named_by_image(None), None);
        // The guessing variant keeps its old contract for callers that need a value.
        assert_eq!(
            m.infer_service_type_from_image(Some("busybox:latest")),
            "openclaw"
        );
        assert_eq!(
            m.infer_service_type_from_image(Some(IRONCLAW_IMAGE)),
            "ironclaw"
        );
    }

    /// An .env left saying `openclaw` for a container running an ironclaw image used to win,
    /// and `ensure_env_file` then rewrote the image to the openclaw default — so the next
    /// recreate started the wrong product on the instance's data. The image decides now.
    #[test]
    fn test_ensure_env_file_keeps_ironclaw_image_when_env_file_says_openclaw() {
        let dir = tempfile::tempdir().unwrap();
        let m = test_manager(dir.path());
        let inst = test_instance("stale-agent", Some(IRONCLAW_IMAGE), None);
        std::fs::write(m.env_path("stale-agent"), "SERVICE_TYPE=openclaw\n").unwrap();

        m.ensure_env_file(&inst, OPENCLAW_IMAGE, None, None, None)
            .unwrap();

        let written = std::fs::read_to_string(m.env_path("stale-agent")).unwrap();
        assert!(
            written.contains(&format!("OPENCLAW_IMAGE={}", IRONCLAW_IMAGE)),
            "image was rewritten away from ironclaw: {}",
            written
        );
        assert!(written.contains("SERVICE_TYPE=ironclaw"), "{}", written);
    }

    #[test]
    fn test_ensure_env_file_still_repairs_an_image_that_contradicts_a_known_service_type() {
        let dir = tempfile::tempdir().unwrap();
        let m = test_manager(dir.path());
        // service_type is known from the container itself, so an openclaw image on an
        // ironclaw instance is still corrected to the ironclaw default.
        let inst = test_instance("mixed-agent", Some(OPENCLAW_IMAGE), Some("ironclaw"));

        m.ensure_env_file(&inst, IRONCLAW_IMAGE, None, None, None)
            .unwrap();

        let written = std::fs::read_to_string(m.env_path("mixed-agent")).unwrap();
        assert!(
            written.contains(&format!("OPENCLAW_IMAGE={}", IRONCLAW_IMAGE)),
            "{}",
            written
        );
        assert!(written.contains("SERVICE_TYPE=ironclaw"), "{}", written);
    }

    #[test]
    fn test_build_backup_script_paths_embed_backup_id_and_pid() {
        let script = build_backup_script("20260611T120000Z", "-C /home/agent .");
        assert!(script.contains("TAR=/tmp/backup-20260611T120000Z-$$.tar.gz"));
        assert!(script.contains("RCPT=/tmp/age-r-20260611T120000Z-$$"));
        assert!(script.contains(r#"tar czf "$TAR" -C /home/agent ."#));
    }

    #[test]
    fn test_build_backup_script_cleans_up_and_uploads_with_timeout() {
        let script = build_backup_script("id1", "-C /home/agent .");
        assert!(script.contains(r#"trap 'rm -f "$TAR" "$TAR.age" "$RCPT"' EXIT"#));
        assert!(script.contains("--connect-timeout 30"));
        assert!(script.contains("--max-time 600"));
        assert!(script.contains(r#"-T "$TAR.age" "$BACKUP_URL""#));
    }

    #[test]
    fn test_instance_data_dirs() {
        assert_eq!(
            instance_data_dirs("x", Some("ironclaw")).unwrap(),
            (".ironclaw", "workspace")
        );
        assert_eq!(
            instance_data_dirs("x", Some("openclaw")).unwrap(),
            (".openclaw", "openclaw")
        );
        assert!(instance_data_dirs("x", None).is_err());
        assert!(instance_data_dirs("x", Some("weird")).is_err());
    }
}
