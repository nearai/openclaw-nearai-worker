use std::str::FromStr;
use std::time::Duration;

use aws_sdk_s3::presigning::PresigningConfig;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::ApiError;

const DEFAULT_PRESIGNED_URL_EXPIRY_SECS: u64 = 3600;
/// Presigned PUT URLs only need to outlive a single in-container upload.
const UPLOAD_URL_EXPIRY_SECS: u64 = 1800;

#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub size_bytes: i64,
}

pub struct BackupManager {
    s3: aws_sdk_s3::Client,
    bucket: String,
}

impl BackupManager {
    /// Initialize from env vars. Returns None if BACKUP_S3_BUCKET is not set.
    pub async fn from_env() -> Option<Self> {
        let bucket = std::env::var("BACKUP_S3_BUCKET").ok()?;

        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

        if let Ok(region) = std::env::var("BACKUP_S3_REGION") {
            config_loader = config_loader.region(aws_config::Region::new(region));
        }

        if let Ok(endpoint) = std::env::var("AWS_ENDPOINT_URL") {
            config_loader = config_loader.endpoint_url(endpoint);
        }

        let config = config_loader.load().await;
        let s3 = aws_sdk_s3::Client::new(&config);

        tracing::info!("BackupManager initialized (bucket: {})", bucket);
        Some(Self { s3, bucket })
    }

    /// Generate a presigned PUT URL so the worker container can upload the
    /// encrypted backup directly to S3 — archive bytes never pass through
    /// this process.
    pub async fn upload_url(
        &self,
        instance_name: &str,
        backup_id: &str,
    ) -> Result<String, ApiError> {
        let key = format!("backups/{}/{}.tar.gz.age", instance_name, backup_id);

        let presigned = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .presigned(
                PresigningConfig::builder()
                    .expires_in(Duration::from_secs(UPLOAD_URL_EXPIRY_SECS))
                    .build()
                    .map_err(|e| ApiError::Internal(format!("presign config error: {}", e)))?,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("presign PUT failed: {}", e)))?;

        Ok(presigned.uri().to_string())
    }

    /// Size of an uploaded backup object, used to verify the in-container
    /// upload actually landed in S3.
    pub async fn object_size(&self, instance_name: &str, backup_id: &str) -> Result<i64, ApiError> {
        let key = format!("backups/{}/{}.tar.gz.age", instance_name, backup_id);

        let head = self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("S3 head_object failed: {}", e)))?;

        Ok(head.content_length().unwrap_or(0))
    }

    /// List available backups for an instance.
    pub async fn list_backups(&self, instance_name: &str) -> Result<Vec<BackupInfo>, ApiError> {
        let prefix = format!("backups/{}/", instance_name);

        let resp = self
            .s3
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&prefix)
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("S3 list failed: {}", e)))?;

        let mut backups = Vec::new();
        if let Some(contents) = resp.contents {
            for obj in contents {
                let key = match obj.key() {
                    Some(k) => k,
                    None => continue,
                };
                // Key format: backups/{name}/{timestamp}.tar.gz.age
                let filename = key.strip_prefix(&prefix).unwrap_or(key);
                let id = filename.strip_suffix(".tar.gz.age").unwrap_or(filename);

                let timestamp = chrono::NaiveDateTime::parse_from_str(id, "%Y%m%dT%H%M%SZ")
                    .ok()
                    .map(|dt| dt.and_utc())
                    .unwrap_or_else(Utc::now);

                backups.push(BackupInfo {
                    id: id.to_string(),
                    timestamp,
                    size_bytes: obj.size.unwrap_or(0),
                });
            }
        }

        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(backups)
    }

    /// Generate a presigned download URL for a backup.
    /// `expiry_secs` defaults to 3600 (1 hour) when None.
    pub async fn download_url(
        &self,
        instance_name: &str,
        backup_id: &str,
        expiry_secs: Option<u64>,
    ) -> Result<String, ApiError> {
        let expiry = expiry_secs.unwrap_or(DEFAULT_PRESIGNED_URL_EXPIRY_SECS);
        let key = format!("backups/{}/{}.tar.gz.age", instance_name, backup_id);

        let presigned = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .presigned(
                PresigningConfig::builder()
                    .expires_in(Duration::from_secs(expiry))
                    .build()
                    .map_err(|e| ApiError::Internal(format!("presign config error: {}", e)))?,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("presign failed: {}", e)))?;

        Ok(presigned.uri().to_string())
    }
}

/// Build the stdin payload that delivers encryption recipients to the
/// in-container backup script: first line is an X25519 recipient ("age1...")
/// or empty, remaining lines are SSH pubkeys written to a -R file.
///
/// Recipients are validated with the `age` crate before any side effects so
/// bad input fails as 400, not as a shell error mid-backup. Encryption itself
/// happens in the worker container via the age CLI.
pub fn build_backup_stdin(
    age_recipient: Option<&str>,
    ssh_pubkey: &str,
) -> Result<String, ApiError> {
    match age_recipient.map(str::trim) {
        Some(r) if r.parse::<age::x25519::Recipient>().is_ok() => Ok(format!("{}\n", r)),
        Some(r) if age::ssh::Recipient::from_str(r).is_ok() => Ok(format!("\n{}\n", r)),
        Some(_) => Err(ApiError::BadRequest(
            "age_recipient is neither a valid X25519 recipient (age1...) nor an SSH public key"
                .into(),
        )),
        None => {
            let key = ssh_pubkey.trim();
            age::ssh::Recipient::from_str(key).map_err(|e| {
                ApiError::Internal(format!(
                    "instance SSH public key is not age-compatible: {:?}",
                    e
                ))
            })?;
            Ok(format!("\n{}\n", key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X25519_RECIPIENT: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    const SSH_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBPKJsJZLflZQFUP0jXFomSzoJ0dUwbmXrc6J4qDfqyR test";

    #[test]
    fn test_build_backup_stdin_x25519_recipient() {
        let payload = build_backup_stdin(Some(X25519_RECIPIENT), SSH_PUBKEY).unwrap();
        assert_eq!(payload, format!("{}\n", X25519_RECIPIENT));
    }

    #[test]
    fn test_build_backup_stdin_ssh_recipient() {
        let payload = build_backup_stdin(Some(SSH_PUBKEY), "unused").unwrap();
        assert_eq!(payload, format!("\n{}\n", SSH_PUBKEY));
    }

    #[test]
    fn test_build_backup_stdin_invalid_recipient_is_bad_request() {
        let err = build_backup_stdin(Some("not-a-key"), SSH_PUBKEY).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_build_backup_stdin_falls_back_to_instance_pubkey() {
        let payload = build_backup_stdin(None, SSH_PUBKEY).unwrap();
        assert_eq!(payload, format!("\n{}\n", SSH_PUBKEY));
    }

    #[test]
    fn test_build_backup_stdin_rejects_invalid_instance_pubkey() {
        let err = build_backup_stdin(None, "garbage").unwrap_err();
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
