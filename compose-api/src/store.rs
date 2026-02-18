use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub ssh_pubkey: String,
    #[serde(default)]
    pub nearai_api_key: String,
    #[serde(default)]
    pub nearai_api_url: Option<String>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    /// "openclaw" (default) or "ironclaw"
    #[serde(default)]
    pub service_type: Option<String>,
}

#[derive(Debug)]
pub struct InstanceStore {
    instances: HashMap<String, Instance>,
}

impl InstanceStore {
    pub fn new() -> Self {
        Self {
            instances: HashMap::new(),
        }
    }

    /// Bulk-insert discovered instances into the store.
    pub fn populate(&mut self, instances: Vec<Instance>) {
        for inst in instances {
            self.instances.insert(inst.name.clone(), inst);
        }
    }

    pub fn add(&mut self, instance: Instance) {
        self.instances.insert(instance.name.clone(), instance);
    }

    pub fn remove(&mut self, name: &str) {
        self.instances.remove(name);
    }

    pub fn get(&self, name: &str) -> Option<&Instance> {
        self.instances.get(name)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.instances.contains_key(name)
    }

    pub fn set_active(&mut self, name: &str, active: bool) -> Result<(), crate::error::ApiError> {
        if let Some(instance) = self.instances.get_mut(name) {
            instance.active = active;
            Ok(())
        } else {
            Err(crate::error::ApiError::NotFound(format!(
                "Instance {} not found",
                name
            )))
        }
    }

    pub fn set_image(
        &mut self,
        name: &str,
        image: Option<String>,
        image_digest: Option<String>,
    ) -> Result<(), crate::error::ApiError> {
        if let Some(instance) = self.instances.get_mut(name) {
            instance.image = image;
            instance.image_digest = image_digest;
            Ok(())
        } else {
            Err(crate::error::ApiError::NotFound(format!(
                "Instance {} not found",
                name
            )))
        }
    }

    pub fn list(&self) -> Vec<Instance> {
        self.instances.values().cloned().collect()
    }

    /// Returns (gateway_port, ssh_port) - two consecutive ports
    pub fn next_available_ports(&self) -> Result<(u16, u16), crate::error::ApiError> {
        let used_ports: std::collections::HashSet<u16> = self
            .instances
            .values()
            .flat_map(|i| [i.gateway_port, i.ssh_port])
            .collect();

        let mut port = BASE_PORT;
        while let Some(next) = port.checked_add(1) {
            if next >= MAX_PORT {
                break;
            }
            if !used_ports.contains(&port) && !used_ports.contains(&next) {
                return Ok((port, next));
            }
            port = match port.checked_add(PORTS_PER_INSTANCE) {
                Some(p) => p,
                None => break,
            };
        }

        Err(crate::error::ApiError::Conflict(
            "All ports exhausted".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_instance(name: &str, gateway_port: u16, ssh_port: u16) -> Instance {
        Instance {
            name: name.to_string(),
            token: "test-token".to_string(),
            gateway_port,
            ssh_port,
            created_at: Utc::now(),
            ssh_pubkey: "ssh-ed25519 AAAA".to_string(),
            nearai_api_key: "key".to_string(),
            nearai_api_url: None,
            active: true,
            image: None,
            image_digest: None,
            service_type: None,
        }
    }

    #[test]
    fn test_next_available_ports_empty_store() {
        let store = InstanceStore::new();
        let (gw, ssh) = store.next_available_ports().unwrap();
        assert_eq!(gw, BASE_PORT);
        assert_eq!(ssh, BASE_PORT + 1);
    }

    #[test]
    fn test_next_available_ports_with_existing() {
        let mut store = InstanceStore::new();
        store.add(test_instance("a", BASE_PORT, BASE_PORT + 1));
        let (gw, ssh) = store.next_available_ports().unwrap();
        assert_eq!(gw, BASE_PORT + PORTS_PER_INSTANCE);
        assert_eq!(ssh, BASE_PORT + PORTS_PER_INSTANCE + 1);
    }

    #[test]
    fn test_next_available_ports_exhausted() {
        let mut store = InstanceStore::new();
        let mut port = BASE_PORT;
        while port + 1 < MAX_PORT {
            store.add(test_instance(&format!("inst-{}", port), port, port + 1));
            port += PORTS_PER_INSTANCE;
        }
        assert!(store.next_available_ports().is_err());
    }

    #[test]
    fn test_store_crud() {
        let mut store = InstanceStore::new();
        assert!(!store.exists("foo"));

        store.add(test_instance("foo", 19001, 19002));
        assert!(store.exists("foo"));
        assert!(store.get("foo").is_some());
        assert_eq!(store.list().len(), 1);

        store.remove("foo");
        assert!(!store.exists("foo"));
        assert!(store.list().is_empty());
    }

    #[test]
    fn test_store_set_active() {
        let mut store = InstanceStore::new();
        store.add(test_instance("foo", 19001, 19002));
        assert!(store.get("foo").unwrap().active);

        store.set_active("foo", false).unwrap();
        assert!(!store.get("foo").unwrap().active);

        store.set_active("foo", true).unwrap();
        assert!(store.get("foo").unwrap().active);

        assert!(store.set_active("nonexistent", true).is_err());
    }
}
