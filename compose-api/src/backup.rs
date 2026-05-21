use std::io::{Cursor, Read, Write};
use std::str::FromStr;
use std::time::Duration;

use age::ssh::Identity;
use age::{Callbacks, Decryptor, Identity as AgeIdentity};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::presigning::PresigningConfig;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use secrecy::SecretString;
use serde::Serialize;

use crate::error::ApiError;

/// Max plaintext instance data (tar) after decrypt+decompress — keep in sync with `MAX_EXPORT_BYTES` in main.
const MAX_BACKUP_PLAINTEXT_BYTES: usize = 512 * 1024 * 1024;
/// Max ciphertext size accepted from S3 (slightly above plaintext cap).
const MAX_BACKUP_CIPHERTEXT_BYTES: usize = 520 * 1024 * 1024;
const MAX_SSH_PRIVATE_KEY_BYTES: usize = 256 * 1024;

#[derive(Clone)]
struct StaticPassphraseCallbacks(SecretString);

impl Callbacks for StaticPassphraseCallbacks {
    fn display_message(&self, _message: &str) {}

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _description: &str) -> Option<SecretString> {
        Some(self.0.clone())
    }
}

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

    /// Create an encrypted backup from pre-exported instance data.
    /// tar_bytes → gzip → age-encrypt with SSH pubkey → upload to S3.
    pub async fn create_backup(
        &self,
        instance_name: &str,
        ssh_pubkey: &str,
        tar_bytes: Vec<u8>,
    ) -> Result<BackupInfo, ApiError> {
        if tar_bytes.is_empty() {
            return Err(ApiError::Internal(
                "instance data export returned empty data".into(),
            ));
        }

        // Gzip compress
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&tar_bytes)
            .map_err(|e| ApiError::Internal(format!("gzip failed: {}", e)))?;
        let gz_bytes = encoder
            .finish()
            .map_err(|e| ApiError::Internal(format!("gzip finish failed: {}", e)))?;

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
            .map_err(|e| ApiError::Internal(format!("S3 upload failed: {}", e)))?;

        Ok(BackupInfo {
            id: timestamp_str,
            timestamp: now,
            size_bytes: size,
        })
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

    /// Generate a presigned download URL for a backup (~1h expiry).
    pub async fn download_url(
        &self,
        instance_name: &str,
        backup_id: &str,
    ) -> Result<String, ApiError> {
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
                    .map_err(|e| ApiError::Internal(format!("presign config error: {}", e)))?,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("presign failed: {}", e)))?;

        Ok(presigned.uri().to_string())
    }

    /// Download encrypted backup object bytes from S3.
    pub async fn fetch_backup_ciphertext(
        &self,
        instance_name: &str,
        backup_id: &str,
    ) -> Result<Vec<u8>, ApiError> {
        let key = format!("backups/{}/{}.tar.gz.age", instance_name, backup_id);
        let resp = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| match &e {
                SdkError::ServiceError(se) if se.err().is_no_such_key() => {
                    ApiError::NotFound(format!(
                        "Backup '{}' not found for instance '{}'",
                        backup_id, instance_name
                    ))
                }
                _ => ApiError::Internal(format!("S3 download failed: {}", e)),
            })?;

        let agg = resp
            .body
            .collect()
            .await
            .map_err(|e| ApiError::Internal(format!("S3 body read failed: {}", e)))?;
        let bytes = agg.into_bytes().to_vec();
        if bytes.len() > MAX_BACKUP_CIPHERTEXT_BYTES {
            return Err(ApiError::BadRequest(format!(
                "Backup object too large (max {} MiB ciphertext)",
                MAX_BACKUP_CIPHERTEXT_BYTES / (1024 * 1024)
            )));
        }
        Ok(bytes)
    }
}

/// Decrypt an age backup (SSH recipient) and decompress gzip to the raw tar archive
/// produced by `export_instance_data`.
pub fn decrypt_backup_to_tar(
    ciphertext: &[u8],
    ssh_private_key: &str,
    ssh_key_passphrase: Option<&str>,
) -> Result<Vec<u8>, ApiError> {
    if ssh_private_key.is_empty() {
        return Err(ApiError::BadRequest("ssh_private_key is required".into()));
    }
    if ssh_private_key.len() > MAX_SSH_PRIVATE_KEY_BYTES {
        return Err(ApiError::BadRequest("ssh_private_key is too large".into()));
    }

    let identity =
        Identity::from_buffer(Cursor::new(ssh_private_key.as_bytes()), None).map_err(|e| {
            ApiError::BadRequest(format!(
                "invalid SSH private key (expected OpenSSH or PEM): {}",
                e
            ))
        })?;

    if matches!(&identity, Identity::Unsupported(_)) {
        return Err(ApiError::BadRequest(
            "SSH private key type is not supported for backup decryption (use ed25519 or RSA)"
                .into(),
        ));
    }

    let decryptor = Decryptor::new_buffered(Cursor::new(ciphertext)).map_err(|e| {
        ApiError::BadRequest(format!("file is not a valid age-encrypted backup: {}", e))
    })?;

    let mut gz_plain = Vec::new();
    if matches!(&identity, Identity::Encrypted(_)) {
        let passphrase = ssh_key_passphrase.ok_or_else(|| {
            ApiError::BadRequest(
                "SSH private key is passphrase-protected; provide ssh_key_passphrase".into(),
            )
        })?;
        let cb =
            StaticPassphraseCallbacks(SecretString::new(passphrase.to_string().into_boxed_str()));
        let id = identity.with_callbacks(cb);
        let mut r = decryptor
            .decrypt(std::iter::once(&id as &dyn AgeIdentity))
            .map_err(|e| {
                ApiError::BadRequest(format!(
                    "decryption failed (wrong key or passphrase): {}",
                    e
                ))
            })?;
        r.read_to_end(&mut gz_plain)
            .map_err(|e| ApiError::Internal(format!("read decrypted backup stream: {}", e)))?;
    } else {
        let mut r = decryptor
            .decrypt(std::iter::once(&identity as &dyn AgeIdentity))
            .map_err(|e| {
                ApiError::BadRequest(format!(
                    "decryption failed (SSH private key does not match backup): {}",
                    e
                ))
            })?;
        r.read_to_end(&mut gz_plain)
            .map_err(|e| ApiError::Internal(format!("read decrypted backup stream: {}", e)))?;
    }

    if gz_plain.len() > MAX_BACKUP_CIPHERTEXT_BYTES {
        return Err(ApiError::BadRequest(
            "decrypted payload exceeds configured size limit".into(),
        ));
    }

    let mut tar = Vec::new();
    let mut decoder = GzDecoder::new(gz_plain.as_slice());
    decoder.read_to_end(&mut tar).map_err(|e| {
        ApiError::BadRequest(format!("backup is not valid gzip after decrypt: {}", e))
    })?;

    if tar.len() > MAX_BACKUP_PLAINTEXT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "restored tar exceeds {} MiB limit",
            MAX_BACKUP_PLAINTEXT_BYTES / (1024 * 1024)
        )));
    }

    Ok(tar)
}

/// Encrypt data using an SSH public key via the `age` crate.
fn encrypt_with_ssh_pubkey(data: &[u8], ssh_pubkey: &str) -> Result<Vec<u8>, ApiError> {
    let recipient = age::ssh::Recipient::from_str(ssh_pubkey)
        .map_err(|e| ApiError::Internal(format!("invalid SSH public key: {:?}", e)))?;

    let recipient: Box<dyn age::Recipient + Send> = Box::new(recipient);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&*recipient as &dyn age::Recipient))
            .map_err(|e| ApiError::Internal(format!("encryptor init failed: {:?}", e)))?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| ApiError::Internal(format!("age wrap_output failed: {}", e)))?;
    writer
        .write_all(data)
        .map_err(|e| ApiError::Internal(format!("age write failed: {}", e)))?;
    writer
        .finish()
        .map_err(|e| ApiError::Internal(format!("age finish failed: {}", e)))?;

    Ok(encrypted)
}
