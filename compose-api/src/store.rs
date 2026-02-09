use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::ApiError;

fn default_active() -> bool {
    true
}

const BASE_PORT: u16 = 19001;
const MAX_PORT: u16 = 19999;
// Each instance gets 2 consecutive ports: gateway_port and gateway_port+1 (SSH)
const PORTS_PER_INSTANCE: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub name: String,
    pub token: String,
    pub gateway_port: u16,
    pub ssh_port: u16,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub ssh_pubkey: Option<String>,
    #[serde(default)]
    pub nearai_api_key: String,
    #[serde(default = "default_active")]
    pub active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstanceStore {
    instances: HashMap<String, Instance>,
    #[serde(skip)]
    file_path: String,
}

impl InstanceStore {
    pub fn load_or_create(file_path: &str) -> Result<Self, ApiError> {
        let path = Path::new(file_path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ApiError::Internal(format!("Failed to create data directory: {}", e)))?;
        }

        if path.exists() {
            let content = fs::read_to_string(path)
                .map_err(|e| ApiError::Internal(format!("Failed to read store: {}", e)))?;
            let mut store: InstanceStore = serde_json::from_str(&content)
                .map_err(|e| ApiError::Internal(format!("Failed to parse store: {}", e)))?;
            store.file_path = file_path.to_string();
            tracing::info!("Loaded {} instances from store", store.instances.len());
            Ok(store)
        } else {
            tracing::info!("Creating new instance store at {}", file_path);
            Ok(Self {
                instances: HashMap::new(),
                file_path: file_path.to_string(),
            })
        }
    }

    pub fn save(&self) -> Result<(), ApiError> {
        let content = serde_json::to_string_pretty(&self)
            .map_err(|e| ApiError::Internal(format!("Failed to serialize store: {}", e)))?;
        fs::write(&self.file_path, content)
            .map_err(|e| ApiError::Internal(format!("Failed to write store: {}", e)))?;
        Ok(())
    }

    pub fn add(&mut self, instance: Instance) -> Result<(), ApiError> {
        self.instances.insert(instance.name.clone(), instance);
        self.save()
    }

    pub fn remove(&mut self, name: &str) -> Result<(), ApiError> {
        self.instances.remove(name);
        self.save()
    }

    pub fn get(&self, name: &str) -> Option<&Instance> {
        self.instances.get(name)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.instances.contains_key(name)
    }

    pub fn set_active(&mut self, name: &str, active: bool) -> Result<(), ApiError> {
        if let Some(instance) = self.instances.get_mut(name) {
            instance.active = active;
            self.save()
        } else {
            Err(ApiError::NotFound(format!("Instance {} not found", name)))
        }
    }

    pub fn list(&self) -> Vec<Instance> {
        self.instances.values().cloned().collect()
    }

    /// Returns (gateway_port, ssh_port) - two consecutive ports
    pub fn next_available_ports(&self) -> (u16, u16) {
        let used_ports: std::collections::HashSet<u16> = self.instances.values()
            .flat_map(|i| [i.gateway_port, i.ssh_port])
            .collect();

        let mut port = BASE_PORT;
        while port + 1 < MAX_PORT {
            if !used_ports.contains(&port) && !used_ports.contains(&(port + 1)) {
                return (port, port + 1);
            }
            port += PORTS_PER_INSTANCE;
        }

        let base = BASE_PORT + (self.instances.len() as u16 * PORTS_PER_INSTANCE);
        (base, base + 1)
    }
}
