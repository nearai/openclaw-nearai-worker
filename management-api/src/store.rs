use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::ApiError;

const BASE_PORT: u16 = 19001;
const MAX_PORT: u16 = 19999;
// Each user gets 2 consecutive ports: gateway_port and gateway_port+1 (SSH)
const PORTS_PER_USER: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub token: String,
    pub gateway_port: u16,
    pub ssh_port: u16,
    pub container_name: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub ssh_pubkey: Option<String>,
    /// User's NEAR AI API key (stored for container recreation)
    #[serde(default)]
    pub nearai_api_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserStore {
    users: HashMap<String, User>,
    #[serde(skip)]
    file_path: String,
}

impl UserStore {
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
            let mut store: UserStore = serde_json::from_str(&content)
                .map_err(|e| ApiError::Internal(format!("Failed to parse store: {}", e)))?;
            store.file_path = file_path.to_string();
            tracing::info!("Loaded {} users from store", store.users.len());
            Ok(store)
        } else {
            tracing::info!("Creating new user store at {}", file_path);
            Ok(Self {
                users: HashMap::new(),
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

    pub fn add(&mut self, user: User) -> Result<(), ApiError> {
        self.users.insert(user.user_id.clone(), user);
        self.save()
    }

    pub fn remove(&mut self, user_id: &str) -> Result<(), ApiError> {
        self.users.remove(user_id);
        self.save()
    }

    pub fn get(&self, user_id: &str) -> Option<&User> {
        self.users.get(user_id)
    }

    pub fn list(&self) -> Vec<User> {
        self.users.values().cloned().collect()
    }

    /// Returns (gateway_port, ssh_port) - two consecutive ports
    pub fn next_available_ports(&self) -> (u16, u16) {
        let used_ports: std::collections::HashSet<u16> = self.users.values()
            .flat_map(|u| [u.gateway_port, u.ssh_port])
            .collect();

        // Find next available pair of consecutive ports
        let mut port = BASE_PORT;
        while port + 1 < MAX_PORT {
            if !used_ports.contains(&port) && !used_ports.contains(&(port + 1)) {
                return (port, port + 1);
            }
            port += PORTS_PER_USER;
        }

        // Fallback (should not happen in practice)
        let base = BASE_PORT + (self.users.len() as u16 * PORTS_PER_USER);
        (base, base + 1)
    }
}
