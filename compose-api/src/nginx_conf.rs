use std::path::Path;
use std::process::Command;

use crate::store::User;

/// Writes the nginx backends map file. Returns `true` if the content changed.
///
/// Generated format (one line per user):
/// ```
/// user1.openclaw.example.com http://127.0.0.1:19001;
/// user2.openclaw.example.com http://127.0.0.1:19003;
/// ```
pub fn write_backends_map(users: &[User], domain: &str, map_path: &Path) -> bool {
    let mut lines: Vec<String> = users
        .iter()
        .map(|u| {
            format!(
                "{}.{} http://127.0.0.1:{};",
                u.user_id, domain, u.gateway_port
            )
        })
        .collect();
    lines.sort();
    let new_content = lines.join("\n") + "\n";

    // Read existing content to check if it changed
    let existing = std::fs::read_to_string(map_path).unwrap_or_default();
    if existing == new_content {
        return false;
    }

    // Ensure parent directory exists
    if let Some(parent) = map_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Err(e) = std::fs::write(map_path, &new_content) {
        tracing::error!("Failed to write nginx map file: {}", e);
        return false;
    }

    tracing::info!(
        "Updated nginx backends map ({} entries)",
        users.len()
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
