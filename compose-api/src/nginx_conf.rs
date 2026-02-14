use std::path::Path;
use std::process::Command;

use crate::store::Instance;

/// Writes the nginx backends map file. Returns `true` if the content changed.
///
/// Generated format (one line per instance):
/// ```
/// brave-tiger.openclaw.example.com http://127.0.0.1:19001;
/// ```
pub fn write_backends_map(instances: &[Instance], domain: &str, map_path: &Path) -> bool {
    let mut lines: Vec<String> = instances
        .iter()
        .filter(|i| i.active)
        .map(|i| format!("{}.{} http://127.0.0.1:{};", i.name, domain, i.gateway_port))
        .collect();
    lines.sort();
    let new_content = lines.join("\n") + "\n";

    let existing = std::fs::read_to_string(map_path).unwrap_or_default();
    if existing == new_content {
        return false;
    }

    if let Some(parent) = map_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Err(e) = std::fs::write(map_path, &new_content) {
        tracing::error!("Failed to write nginx map file: {}", e);
        return false;
    }

    tracing::info!("Updated nginx backends map ({} entries)", lines.len());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_instance(name: &str, port: u16, active: bool) -> Instance {
        Instance {
            name: name.to_string(),
            token: "tok".to_string(),
            gateway_port: port,
            ssh_port: port + 1,
            created_at: chrono::Utc::now(),
            ssh_pubkey: "ssh-ed25519 AAAA".to_string(),
            nearai_api_key: "key".to_string(),
            active,
            image: None,
            image_digest: None,
        }
    }

    #[test]
    fn test_writes_correct_format() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("backends.map");
        let instances = vec![test_instance("brave-tiger", 19001, true)];

        let changed = write_backends_map(&instances, "example.com", &map_path);
        assert!(changed);

        let content = std::fs::read_to_string(&map_path).unwrap();
        assert!(content.contains("brave-tiger.example.com http://127.0.0.1:19001;"));
    }

    #[test]
    fn test_filters_inactive_instances() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("backends.map");
        let instances = vec![
            test_instance("active", 19001, true),
            test_instance("stopped", 19003, false),
        ];

        write_backends_map(&instances, "example.com", &map_path);

        let content = std::fs::read_to_string(&map_path).unwrap();
        assert!(content.contains("active.example.com"));
        assert!(!content.contains("stopped.example.com"));
    }

    #[test]
    fn test_returns_false_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("backends.map");
        let instances = vec![test_instance("a", 19001, true)];

        let first = write_backends_map(&instances, "example.com", &map_path);
        assert!(first);

        let second = write_backends_map(&instances, "example.com", &map_path);
        assert!(!second);
    }
}

/// Sends `nginx -s reload` to the ingress container.
pub fn reload_nginx(container_name: &str) {
    let output = Command::new("docker")
        .args(["exec", container_name, "nginx", "-s", "reload"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            tracing::info!("Nginx reloaded successfully");
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            tracing::warn!("Nginx reload failed: {}", stderr);
        }
        Err(e) => {
            tracing::warn!("Failed to exec nginx reload: {}", e);
        }
    }
}
