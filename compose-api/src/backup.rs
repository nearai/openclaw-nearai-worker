use std::io::Write;
use std::str::FromStr;
use std::time::Duration;

use aws_sdk_s3::presigning::PresigningConfig;
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;

use crate::compose::ComposeManager;

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

    /// Create an encrypted backup of an instance's workspace.
    /// Exports workspace → gzip → age-encrypt with SSH pubkey → upload to S3.
    pub async fn create_backup(
        &self,
        instance_name: &str,
        ssh_pubkey: &str,
        compose: &ComposeManager,
    ) -> Result<BackupInfo, String> {
        // Export workspace tar from container
        let tar_bytes = compose
            .export_workspace(instance_name)
            .map_err(|e| format!("export failed: {}", e))?;

        if tar_bytes.is_empty() {
            return Err("workspace export returned empty data".into());
        }

        // Gzip compress
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&tar_bytes)
            .map_err(|e| format!("gzip failed: {}", e))?;
        let gz_bytes = encoder
            .finish()
            .map_err(|e| format!("gzip finish failed: {}", e))?;

        // Encrypt with age using SSH public key
        let encrypted = encrypt_with_ssh_pubkey(&gz_bytes, ssh_pubkey)?;

        // Upload to S3
        let now = Utc::now();
        let timestamp_str = now.format("%Y%m%dT%H%M%SZ").to_string();
        let key = format!("backups/{}/{}.tar.gz.age", instance_name, timestamp_str);

        let size = encrypted.len() as i64;

        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(encrypted.into())
            .send()
            .await
            .map_err(|e| format!("S3 upload failed: {}", e))?;

        Ok(BackupInfo {
            id: timestamp_str,
            timestamp: now,
            size_bytes: size,
        })
    }

    /// List available backups for an instance.
    pub async fn list_backups(&self, instance_name: &str) -> Result<Vec<BackupInfo>, String> {
        let prefix = format!("backups/{}/", instance_name);

        let resp = self
            .s3
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&prefix)
            .send()
            .await
            .map_err(|e| format!("S3 list failed: {}", e))?;

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

    /// Generate a presigned download URL for a backup (~1h expiry).
    pub async fn download_url(
        &self,
        instance_name: &str,
        backup_id: &str,
    ) -> Result<String, String> {
        let key = format!("backups/{}/{}.tar.gz.age", instance_name, backup_id);

        let presigned = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .presigned(
                PresigningConfig::builder()
                    .expires_in(Duration::from_secs(3600))
                    .build()
                    .map_err(|e| format!("presign config error: {}", e))?,
            )
            .await
            .map_err(|e| format!("presign failed: {}", e))?;

        Ok(presigned.uri().to_string())
    }
}

/// Encrypt data using an SSH public key via the `age` crate.
fn encrypt_with_ssh_pubkey(data: &[u8], ssh_pubkey: &str) -> Result<Vec<u8>, String> {
    let recipient = age::ssh::Recipient::from_str(ssh_pubkey)
        .map_err(|e| format!("invalid SSH public key: {:?}", e))?;

    let recipient: Box<dyn age::Recipient + Send> = Box::new(recipient);
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&*recipient as &dyn age::Recipient))
        .map_err(|e| format!("encryptor init failed: {:?}", e))?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| format!("age wrap_output failed: {}", e))?;
    writer
        .write_all(data)
        .map_err(|e| format!("age write failed: {}", e))?;
    writer
        .finish()
        .map_err(|e| format!("age finish failed: {}", e))?;

    Ok(encrypted)
}
