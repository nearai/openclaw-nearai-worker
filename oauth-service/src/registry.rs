use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredInstanceToken {
    pub instance_name: String,
    pub token_hash: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedRegistry {
    instances: Vec<StoredInstanceToken>,
}

#[derive(Debug, Clone)]
pub struct InstanceTokenRegistry {
    path: Arc<PathBuf>,
    entries: Arc<RwLock<BTreeMap<String, StoredInstanceToken>>>,
}

impl InstanceTokenRegistry {
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self, ApiError> {
        let path = path.into();
        let entries = load_entries(&path).await?;
        Ok(Self {
            path: Arc::new(path),
            entries: Arc::new(RwLock::new(entries)),
        })
    }

    pub async fn upsert(&self, instance_name: &str, gateway_token: &str) -> Result<(), ApiError> {
        let mut entries = self.entries.write().await;
        entries.insert(
            instance_name.to_string(),
            StoredInstanceToken {
                instance_name: instance_name.to_string(),
                token_hash: hash_gateway_token(gateway_token),
                updated_at: Utc::now(),
            },
        );
        persist_entries(self.path.as_ref(), &entries).await
    }

    pub async fn remove(&self, instance_name: &str) -> Result<(), ApiError> {
        let mut entries = self.entries.write().await;
        entries.remove(instance_name);
        persist_entries(self.path.as_ref(), &entries).await
    }

    pub async fn replace_all(
        &self,
        desired: impl IntoIterator<Item = (String, String)>,
    ) -> Result<(), ApiError> {
        let mut entries = BTreeMap::new();
        for (instance_name, gateway_token) in desired {
            entries.insert(
                instance_name.clone(),
                StoredInstanceToken {
                    instance_name,
                    token_hash: hash_gateway_token(&gateway_token),
                    updated_at: Utc::now(),
                },
            );
        }

        persist_entries(self.path.as_ref(), &entries).await?;

        let mut guard = self.entries.write().await;
        *guard = entries;
        Ok(())
    }
}

pub fn hash_gateway_token(token: &str) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(token.as_bytes()))
}

pub async fn authenticate_gateway_token(
    registry: &InstanceTokenRegistry,
    gateway_token: &str,
) -> Option<String> {
    let hashed = hash_gateway_token(gateway_token);
    let entries = registry.entries.read().await;
    let mut matched_name: Option<String> = None;
    for entry in entries.values() {
        let is_match = constant_time_token_eq(&hashed, &entry.token_hash);
        if is_match && matched_name.is_none() {
            matched_name = Some(entry.instance_name.clone());
        }
    }
    matched_name
}

pub(crate) fn constant_time_token_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max_len = ab.len().max(bb.len());
    let mut diff: u8 = 0;
    for i in 0..max_len {
        let x = ab.get(i).copied().unwrap_or(0);
        let y = bb.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0 && ab.len() == bb.len()
}

async fn load_entries(path: &Path) -> Result<BTreeMap<String, StoredInstanceToken>, ApiError> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(err) => {
            return Err(ApiError::Internal(format!(
                "Failed to read OAuth registry {}: {}",
                path.display(),
                err
            )))
        }
    };

    let persisted: PersistedRegistry = serde_json::from_str(&content).map_err(|err| {
        ApiError::Internal(format!(
            "Failed to parse OAuth registry {}: {}",
            path.display(),
            err
        ))
    })?;

    let mut entries = BTreeMap::new();
    for entry in persisted.instances {
        entries.insert(entry.instance_name.clone(), entry);
    }
    Ok(entries)
}

async fn persist_entries(
    path: &Path,
    entries: &BTreeMap<String, StoredInstanceToken>,
) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            ApiError::Internal(format!(
                "Failed to create OAuth registry directory {}: {}",
                parent.display(),
                err
            ))
        })?;
    }

    let payload = PersistedRegistry {
        instances: entries.values().cloned().collect(),
    };
    let json = serde_json::to_vec_pretty(&payload).map_err(|err| {
        ApiError::Internal(format!(
            "Failed to serialize OAuth registry {}: {}",
            path.display(),
            err
        ))
    })?;

    let tmp_path = path.with_extension("tmp");
    tokio::fs::write(&tmp_path, json).await.map_err(|err| {
        ApiError::Internal(format!(
            "Failed to write OAuth registry {}: {}",
            tmp_path.display(),
            err
        ))
    })?;
    tokio::fs::rename(&tmp_path, path).await.map_err(|err| {
        ApiError::Internal(format!(
            "Failed to replace OAuth registry {}: {}",
            path.display(),
            err
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    #[tokio::test]
    async fn authenticate_gateway_token_matches_stored_hash() {
        let tempdir = tempdir().unwrap();
        let registry = InstanceTokenRegistry::load(tempdir.path().join("oauth.json"))
            .await
            .unwrap();

        registry.upsert("pale-crab", "secret-token").await.unwrap();

        let matched = authenticate_gateway_token(&registry, "secret-token").await;
        assert_eq!(matched.as_deref(), Some("pale-crab"));
    }

    #[tokio::test]
    async fn replace_all_rewrites_registry_snapshot() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("oauth.json");
        let registry = InstanceTokenRegistry::load(&path).await.unwrap();

        registry
            .replace_all([
                ("a".to_string(), "token-a".to_string()),
                ("b".to_string(), "token-b".to_string()),
            ])
            .await
            .unwrap();

        let persisted = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(persisted.contains("\"instance_name\": \"a\""));
        assert!(persisted.contains("\"instance_name\": \"b\""));
    }
}
