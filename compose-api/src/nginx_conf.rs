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
        .map(|i| {
            format!(
                "{}.{} http://127.0.0.1:{};",
                i.name, domain, i.gateway_port
            )
        })
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

    tracing::info!(
        "Updated nginx backends map ({} entries)",
        lines.len()
    );
    true
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
