use std::collections::HashSet;

use serde::Deserialize;

pub struct CloudflareDns {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct ListResponse {
    result: Vec<DnsRecord>,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
}

impl CloudflareDns {
    pub fn new(api_token: &str, zone_id: &str) -> Self {
        let client = reqwest::Client::builder()
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", api_token).parse().unwrap(),
                );
                headers.insert(
                    reqwest::header::CONTENT_TYPE,
                    "application/json".parse().unwrap(),
                );
                headers
            })
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            base_url: format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                zone_id
            ),
        }
    }

    /// Creates or updates a TXT record: `_dstack-app-address.{user_id}.{domain}` → `{app_id}:{port}`
    pub async fn ensure_txt_record(
        &self,
        user_id: &str,
        domain: &str,
        app_id: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        let record_name = format!("_dstack-app-address.{}.{}", user_id, domain);
        let content = format!("{}:{}", app_id, port);

        // Check if record already exists
        let existing = self.find_txt_record(&record_name).await?;

        if let Some(record_id) = existing {
            // Update existing record
            let body = serde_json::json!({
                "type": "TXT",
                "name": record_name,
                "content": content,
                "ttl": 60,
            });

            let resp = self
                .client
                .put(format!("{}/{}", self.base_url, record_id))
                .json(&body)
                .send()
                .await?;

            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Cloudflare PUT failed for {}: {}", record_name, text);
            }

            tracing::info!("Updated DNS TXT record: {} → {}", record_name, content);
        } else {
            // Create new record
            let body = serde_json::json!({
                "type": "TXT",
                "name": record_name,
                "content": content,
                "ttl": 60,
            });

            let resp = self.client.post(&self.base_url).json(&body).send().await?;

            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Cloudflare POST failed for {}: {}", record_name, text);
            }

            tracing::info!("Created DNS TXT record: {} → {}", record_name, content);
        }

        Ok(())
    }

    /// Deletes the TXT record for a user.
    pub async fn delete_txt_record(&self, user_id: &str, domain: &str) -> anyhow::Result<()> {
        let record_name = format!("_dstack-app-address.{}.{}", user_id, domain);

        if let Some(record_id) = self.find_txt_record(&record_name).await? {
            let resp = self
                .client
                .delete(format!("{}/{}", self.base_url, record_id))
                .send()
                .await?;

            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Cloudflare DELETE failed for {}: {}", record_name, text);
            }

            tracing::info!("Deleted DNS TXT record: {}", record_name);
        } else {
            tracing::debug!("DNS TXT record not found (already deleted?): {}", record_name);
        }

        Ok(())
    }

    /// Syncs all TXT records: creates missing ones, removes orphaned ones.
    pub async fn sync_all_records(
        &self,
        user_ids: &[String],
        domain: &str,
        app_id: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        let prefix = format!("_dstack-app-address.");
        let suffix = format!(".{}", domain);

        // List all existing _dstack-app-address.*.domain TXT records
        let existing_records = self.list_txt_records(&prefix, &suffix).await?;

        let desired: HashSet<String> = user_ids
            .iter()
            .map(|uid| format!("_dstack-app-address.{}.{}", uid, domain))
            .collect();

        let existing_names: HashSet<String> =
            existing_records.iter().map(|r| r.name.clone()).collect();

        // Create missing records
        for uid in user_ids {
            let name = format!("_dstack-app-address.{}.{}", uid, domain);
            if !existing_names.contains(&name) {
                if let Err(e) = self.ensure_txt_record(uid, domain, app_id, port).await {
                    tracing::warn!("Failed to create DNS record for {}: {}", uid, e);
                }
            }
        }

        // Remove orphaned records (skip wildcard record managed by dstack-ingress)
        let wildcard_name = format!("_dstack-app-address.*.{}", domain);
        for record in &existing_records {
            if record.name == wildcard_name {
                continue;
            }
            if !desired.contains(&record.name) {
                tracing::info!("Removing orphaned DNS record: {}", record.name);
                let resp = self
                    .client
                    .delete(format!("{}/{}", self.base_url, record.id))
                    .send()
                    .await;
                if let Err(e) = resp {
                    tracing::warn!("Failed to delete orphaned DNS record {}: {}", record.name, e);
                }
            }
        }

        Ok(())
    }

    async fn find_txt_record(&self, name: &str) -> anyhow::Result<Option<String>> {
        let resp = self
            .client
            .get(&self.base_url)
            .query(&[("type", "TXT"), ("name", name)])
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Cloudflare GET failed: {}", text);
        }

        let body: ListResponse = resp.json().await?;
        Ok(body.result.first().map(|r| r.id.clone()))
    }

    async fn list_txt_records(
        &self,
        prefix: &str,
        suffix: &str,
    ) -> anyhow::Result<Vec<DnsRecord>> {
        let mut records = Vec::new();
        let mut page = 1u32;

        loop {
            let resp = self
                .client
                .get(&self.base_url)
                .query(&[
                    ("type", "TXT"),
                    ("per_page", "100"),
                    ("page", &page.to_string()),
                ])
                .send()
                .await?;

            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Cloudflare list failed: {}", text);
            }

            let body: ListResponse = resp.json().await?;
            if body.result.is_empty() {
                break;
            }

            for record in body.result {
                if record.name.starts_with(prefix) && record.name.ends_with(suffix) {
                    records.push(record);
                }
            }

            page += 1;
        }

        Ok(records)
    }
}
