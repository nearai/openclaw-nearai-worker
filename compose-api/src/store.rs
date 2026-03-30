use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

fn default_active() -> bool {
    true
}

const DEFAULT_BASE_PORT: u16 = 19001;
const DEFAULT_MAX_PORT: u16 = 29999;
// Each instance gets 2 consecutive ports: gateway_port and gateway_port+1 (SSH)
const PORTS_PER_INSTANCE: u16 = 2;

fn parse_port_env(var_name: &str, default: u16) -> u16 {
    match std::env::var(var_name) {
        Ok(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(e) => {
                tracing::warn!(
                    "failed to parse {}='{}' as u16 ({}); falling back to default port {}",
                    var_name,
                    raw,
                    e,
                    default
                );
                default
            }
        },
        Err(std::env::VarError::NotPresent) => default,
        Err(e) => {
            tracing::warn!(
                "failed to read {} from environment ({}); falling back to default port {}",
                var_name,
                e,
                default
            );
            default
        }
    }
}

/// Try to bind a port on 0.0.0.0. Returns the listener on success so the
/// caller can hold it while probing the next port in a pair.
fn try_bind(port: u16) -> Option<TcpListener> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    match TcpListener::bind(addr) {
        Ok(listener) => Some(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => None,
        Err(e) => {
            tracing::error!(
                "unexpected error probing port {}: {}; treating as unavailable",
                port,
                e
            );
            None
        }
    }
}

/// Check if a pair of ports is free by binding both. The first port's listener
/// is held while probing the second to avoid a TOCTOU race between the two.
fn are_ports_free(p1: u16, p2: u16) -> bool {
    let _listener1 = match try_bind(p1) {
        Some(l) => l,
        None => return false,
    };
    try_bind(p2).is_some()
}

/// Resolved port range, validated once at startup.
#[derive(Debug, Clone, Copy)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// Read and validate port range from environment. Call once at startup.
    pub fn from_env() -> Self {
        let start = parse_port_env("PORT_RANGE_START", DEFAULT_BASE_PORT);
        let end = parse_port_env("PORT_RANGE_END", DEFAULT_MAX_PORT);

        assert!(
            end > start,
            "Invalid port range: PORT_RANGE_END ({}) must be greater than PORT_RANGE_START ({})",
            end,
            start
        );

        let available_ports = (end as u32) - (start as u32) + 1;
        assert!(
            available_ports >= PORTS_PER_INSTANCE as u32,
            "Invalid port range: [{}, {}] provides {} ports, but at least {} are required for one instance",
            start, end, available_ports, PORTS_PER_INSTANCE
        );

        tracing::info!("port range: {}-{} ({} ports)", start, end, available_ports);
        Self { start, end }
    }
}

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
    /// Memory limit override (e.g. "1g", "2g")
    #[serde(default)]
    pub mem_limit: Option<String>,
    /// CPU limit override (e.g. "2", "4")
    #[serde(default)]
    pub cpus: Option<String>,
    /// Container storage limit override (e.g. "10G", "20G")
    #[serde(default)]
    pub storage_size: Option<String>,
    /// Additional environment variables (e.g. CHANNEL_RELAY_URL, CHANNEL_RELAY_API_KEY).
    #[serde(default)]
    pub extra_env: Option<HashMap<String, String>>,
}

#[derive(Debug)]
pub struct InstanceStore {
    instances: HashMap<String, Instance>,
    port_range: PortRange,
}

impl InstanceStore {
    pub fn new(port_range: PortRange) -> Self {
        Self {
            instances: HashMap::new(),
            port_range,
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

    /// Returns an iterator over all instance references (avoids cloning).
    pub fn all(&self) -> impl Iterator<Item = &Instance> {
        self.instances.values()
    }

    /// Returns (gateway_port, ssh_port) - two consecutive ports.
    ///
    /// Checks both the in-memory store AND the OS (via a bind probe) to avoid
    /// conflicts with ports held by containers/processes not tracked by the store
    /// (e.g. after a CVM restart where Docker state drifted from the store).
    pub fn next_available_ports(&self) -> Result<(u16, u16), crate::error::ApiError> {
        let used_ports: std::collections::HashSet<u16> = self
            .instances
            .values()
            .flat_map(|i| [i.gateway_port, i.ssh_port])
            .collect();

        let start = self.port_range.start;
        let end = self.port_range.end;
        let mut port = start;
        while let Some(next) = port.checked_add(1) {
            if next > end {
                break;
            }
            if !used_ports.contains(&port)
                && !used_ports.contains(&next)
                && are_ports_free(port, next)
            {
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

    fn range(start: u16, end: u16) -> PortRange {
        PortRange { start, end }
    }

    fn default_range() -> PortRange {
        range(DEFAULT_BASE_PORT, DEFAULT_MAX_PORT)
    }

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
            mem_limit: None,
            cpus: None,
            storage_size: None,
            extra_env: None,
        }
    }

    #[test]
    fn test_next_available_ports_empty_store() {
        let store = InstanceStore::new(default_range());
        let (gw, ssh) = store.next_available_ports().unwrap();
        assert_eq!(gw, DEFAULT_BASE_PORT);
        assert_eq!(ssh, DEFAULT_BASE_PORT + 1);
    }

    #[test]
    fn test_next_available_ports_with_existing() {
        let mut store = InstanceStore::new(default_range());
        store.add(test_instance("a", DEFAULT_BASE_PORT, DEFAULT_BASE_PORT + 1));
        let (gw, ssh) = store.next_available_ports().unwrap();
        assert_eq!(gw, DEFAULT_BASE_PORT + PORTS_PER_INSTANCE);
        assert_eq!(ssh, DEFAULT_BASE_PORT + PORTS_PER_INSTANCE + 1);
    }

    #[test]
    fn test_next_available_ports_exhausted() {
        let mut store = InstanceStore::new(range(50001, 50004));
        let mut port: u16 = 50001;
        while port < 50004 {
            store.add(test_instance(&format!("inst-{}", port), port, port + 1));
            port += PORTS_PER_INSTANCE;
        }
        assert!(store.next_available_ports().is_err());
    }

    #[test]
    fn test_next_available_ports_custom_range() {
        let store = InstanceStore::new(range(30001, 30010));
        let (gw, ssh) = store.next_available_ports().unwrap();
        assert_eq!(gw, 30001);
        assert_eq!(ssh, 30002);

        // With one instance, should get the next pair
        let mut store = InstanceStore::new(range(30001, 30010));
        store.add(test_instance("a", 30001, 30002));
        let (gw, ssh) = store.next_available_ports().unwrap();
        assert_eq!(gw, 30003);
        assert_eq!(ssh, 30004);
    }

    #[test]
    fn test_next_available_ports_end_inclusive() {
        // Range of exactly 2 ports — should fit one instance
        let store = InstanceStore::new(range(40001, 40002));
        let (gw, ssh) = store.next_available_ports().unwrap();
        assert_eq!(gw, 40001);
        assert_eq!(ssh, 40002);
    }

    #[test]
    fn test_next_available_ports_skips_os_bound_port() {
        // Bind a port in a high range unlikely to conflict with other tests
        let held = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 48001)).unwrap();
        let store = InstanceStore::new(range(48001, 48006));
        let (gw, ssh) = store.next_available_ports().unwrap();
        // Should skip 48001/48002 because 48001 is bound at OS level
        assert_eq!(gw, 48003);
        assert_eq!(ssh, 48004);
        drop(held);
    }

    #[test]
    fn test_store_crud() {
        let mut store = InstanceStore::new(default_range());
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
        let mut store = InstanceStore::new(default_range());
        store.add(test_instance("foo", 19001, 19002));
        assert!(store.get("foo").unwrap().active);

        store.set_active("foo", false).unwrap();
        assert!(!store.get("foo").unwrap().active);

        store.set_active("foo", true).unwrap();
        assert!(store.get("foo").unwrap().active);

        assert!(store.set_active("nonexistent", true).is_err());
    }
}
