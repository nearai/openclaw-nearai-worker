use bollard::models::{
    ContainerCreateBody, HostConfig, Mount, MountTypeEnum, NetworkCreateRequest, PortBinding,
};
use bollard::query_parameters::{
    CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
    RestartContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::Docker;
use std::collections::HashMap;

use crate::error::ApiError;

pub struct DockerManager {
    client: Docker,
}

impl DockerManager {
    pub async fn new() -> Result<Self, ApiError> {
        let client = Docker::connect_with_local_defaults()
            .map_err(|e| ApiError::Internal(format!("Failed to connect to Docker: {}", e)))?;
        
        // Test connection
        client.ping().await
            .map_err(|e| ApiError::Internal(format!("Failed to ping Docker: {}", e)))?;
        
        tracing::info!("Connected to Docker daemon");
        Ok(Self { client })
    }

    pub async fn ensure_network(&self, network_name: &str) -> Result<(), ApiError> {
        let networks = self.client
            .list_networks(None)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to list networks: {}", e)))?;

        let exists = networks.iter().any(|n| {
            n.name.as_ref().map(|name| name == network_name).unwrap_or(false)
        });

        if !exists {
            self.client
                .create_network(NetworkCreateRequest {
                    name: network_name.to_string(),
                    driver: Some("bridge".to_string()),
                    ..Default::default()
                })
                .await
                .map_err(|e| ApiError::Internal(format!("Failed to create network: {}", e)))?;
            
            tracing::info!("Created Docker network: {}", network_name);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_openclaw_container(
        &self,
        container_name: &str,
        image: &str,
        nearai_api_key: &str,
        gateway_token: &str,
        gateway_port: u16,
        ssh_port: u16,
        ssh_pubkey: Option<&str>,
        network_name: &str,
    ) -> Result<(), ApiError> {
        // Check if container already exists
        let containers = self.client
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters: Some(HashMap::from([("name".to_string(), vec![container_name.to_string()])])),
                ..Default::default()
            }))
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to list containers: {}", e)))?;

        if !containers.is_empty() {
            return Err(ApiError::Conflict(format!("Container {} already exists", container_name)));
        }

        // Volume name for persistent data
        let volume_name = format!("{}-data", container_name);

        // Environment variables
        let mut env = vec![
            format!("HOME=/home/agent"),
            format!("TERM=xterm-256color"),
            format!("NEARAI_API_KEY={}", nearai_api_key),
            format!("OPENCLAW_GATEWAY_TOKEN={}", gateway_token),
            format!("OPENCLAW_GATEWAY_BIND=lan"),
            format!("OPENCLAW_FORCE_CONFIG_REGEN=1"),
            format!("OPENCLAW_AUTO_APPROVE_DEVICES=1"),
        ];

        // Add SSH public key if provided
        if let Some(pubkey) = ssh_pubkey {
            env.push(format!("SSH_AUTHORIZED_KEYS={}", pubkey));
        }

        // Container labels for management
        let mut labels = HashMap::new();
        labels.insert("openclaw.managed".to_string(), "true".to_string());
        labels.insert("openclaw.user".to_string(), container_name.replace("openclaw-", ""));

        // Port bindings for direct access (gateway + SSH)
        let mut port_bindings = HashMap::new();
        
        // Gateway port mapping (container 18789 -> host gateway_port)
        port_bindings.insert(
            "18789/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some(gateway_port.to_string()),
            }]),
        );
        
        // SSH port mapping (container 22 -> host ssh_port)
        port_bindings.insert(
            "22/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some(ssh_port.to_string()),
            }]),
        );

        let host_config = HostConfig {
            network_mode: Some(network_name.to_string()),
            port_bindings: Some(port_bindings),
            mounts: Some(vec![
                Mount {
                    target: Some("/home/agent/.openclaw".to_string()),
                    source: Some(volume_name.clone()),
                    typ: Some(MountTypeEnum::VOLUME),
                    ..Default::default()
                },
                Mount {
                    target: Some("/home/agent/openclaw".to_string()),
                    source: Some(format!("{}-workspace", container_name)),
                    typ: Some(MountTypeEnum::VOLUME),
                    ..Default::default()
                },
            ]),
            init: Some(true),
            restart_policy: Some(bollard::models::RestartPolicy {
                name: Some(bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED),
                ..Default::default()
            }),
            ..Default::default()
        };

        let config = ContainerCreateBody {
            image: Some(image.to_string()),
            env: Some(env),
            labels: Some(labels),
            host_config: Some(host_config),
            cmd: Some(vec![
                "openclaw".to_string(),
                "gateway".to_string(),
                "run".to_string(),
                "--bind".to_string(),
                "lan".to_string(),
                "--port".to_string(),
                "18789".to_string(),
                "--verbose".to_string(),
            ]),
            ..Default::default()
        };

        self.client
            .create_container(
                Some(CreateContainerOptions {
                    name: Some(container_name.to_string()),
                    platform: String::new(),
                }),
                config,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to create container: {}", e)))?;

        tracing::info!("Created container: {} (gateway:{}, ssh:{})", container_name, gateway_port, ssh_port);
        Ok(())
    }

    pub async fn start_container(&self, container_name: &str) -> Result<(), ApiError> {
        self.client
            .start_container(container_name, None::<StartContainerOptions>)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to start container: {}", e)))?;
        
        tracing::info!("Started container: {}", container_name);
        Ok(())
    }

    pub async fn stop_container(&self, container_name: &str) -> Result<(), ApiError> {
        self.client
            .stop_container(container_name, Some(StopContainerOptions { t: Some(10), signal: None }))
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to stop container: {}", e)))?;
        
        tracing::info!("Stopped container: {}", container_name);
        Ok(())
    }

    pub async fn restart_container(&self, container_name: &str) -> Result<(), ApiError> {
        self.client
            .restart_container(container_name, Some(RestartContainerOptions { t: Some(10), signal: None }))
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to restart container: {}", e)))?;
        
        tracing::info!("Restarted container: {}", container_name);
        Ok(())
    }

    pub async fn remove_container(&self, container_name: &str) -> Result<(), ApiError> {
        self.client
            .remove_container(
                container_name,
                Some(RemoveContainerOptions {
                    force: true,
                    v: true, // Remove volumes
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to remove container: {}", e)))?;
        
        tracing::info!("Removed container: {}", container_name);
        Ok(())
    }

    pub async fn get_container_status(&self, container_name: &str) -> Result<String, ApiError> {
        let containers = self.client
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters: Some(HashMap::from([("name".to_string(), vec![format!("^/{}$", container_name)])])),
                ..Default::default()
            }))
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to list containers: {}", e)))?;

        if let Some(container) = containers.first() {
            Ok(container.state.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()))
        } else {
            Ok("not_found".to_string())
        }
    }
}
