//! Configuration management for the secure gateway
//!
//! This module handles loading, parsing, and validating gateway configuration
//! from various sources (files, environment variables).

use anyhow::{anyhow, Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use crate::protocols::ProtocolType;
use crate::security::SecurityMode;

/// Main configuration structure for the gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// General settings
    pub general: GeneralConfig,
    
    /// Security settings
    pub security: SecurityConfig,
    
    /// Protocol-specific settings
    pub protocols: ProtocolsConfig,
    
    /// Translation rules
    pub translation_rules: Vec<TranslationRule>,
}

/// General gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Name of this gateway instance
    pub name: String,
    
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    /// Number of worker threads (0 = use number of CPU cores)
    #[serde(default)]
    pub workers: usize,
    
    /// Input queue size
    #[serde(default = "default_queue_size")]
    pub queue_size: usize,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_queue_size() -> usize {
    1000
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Path to key storage file (if persistent)
    pub key_storage_path: Option<String>,
    
    /// Default encryption key ID
    pub default_encryption_key: String,
    
    /// Default signing key ID (for signing)
    pub default_signing_key: String,
    
    /// Default security mode for outgoing messages
    #[serde(default)]
    pub default_security_mode: SecurityMode,
    
    /// Key rotation interval in days (None = manual rotation)
    pub key_rotation_days: Option<u64>,
}

/// Protocol-specific configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolsConfig {
    /// MIL-STD-1553 configuration
    pub mil_std_1553: MilStd1553Config,
    
    /// EtherNet/IP configuration
    pub ethernet_ip: EthernetIpConfig,
}

/// MIL-STD-1553 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MilStd1553Config {
    /// Interface address or device
    pub interface: String,
    
    /// Simulated mode (for testing without hardware)
    #[serde(default)]
    pub simulated: bool,
    
    /// Valid remote terminal addresses
    pub remote_terminals: Vec<u8>,
}

/// EtherNet/IP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetIpConfig {
    /// IP address to bind to
    pub bind_address: String,
    
    /// Port number to listen on
    pub port: u16,
    
    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    
    /// Session idle timeout in seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    300 // 5 minutes
}

/// Translation rule for protocol conversion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationRule {
    /// Rule name/identifier
    pub name: String,
    
    /// Source protocol
    pub source: ProtocolType,
    
    /// Target protocol
    pub target: ProtocolType,
    
    /// Priority (lower = higher priority)
    #[serde(default = "default_priority")]
    pub priority: u8,
    
    /// Filter criteria for matching source messages
    pub filter: HashMap<String, String>,
    
    /// Transformation to apply during translation
    pub transform: Option<TransformType>,
    
    /// Security mode to apply to the translated message
    #[serde(default)]
    pub security_mode: SecurityMode,
}

fn default_priority() -> u8 {
    5
}

/// Transformation types for message conversion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransformType {
    /// Map fields by name
    FieldMap(HashMap<String, String>),
    
    /// Custom transformation module
    Custom(String),
    
    /// Send as-is (just protocol encapsulation)
    Identity,
}

impl Config {
    /// Load configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config_builder = ::config::Config::builder()
            .add_source(::config::File::from(path.as_ref()))
            .add_source(::config::Environment::with_prefix("GATEWAY").separator("__"));
            
        let settings = config_builder.build()
            .context("Failed to build configuration")?;
            
        let config: Config = settings.try_deserialize()
            .context("Failed to deserialize configuration")?;
            
        config.validate()?;
        info!("Configuration loaded and validated successfully");
        Ok(config)
    }
    
    /// Create a default configuration
    pub fn default() -> Self {
        Self {
            general: GeneralConfig {
                name: "secure-gateway".to_string(),
                log_level: default_log_level(),
                workers: 0,  // Auto-detect
                queue_size: default_queue_size(),
            },
            security: SecurityConfig {
                key_storage_path: Some("keys.bin".to_string()),
                default_encryption_key: "default-encryption".to_string(),
                default_signing_key: "default-signing".to_string(),
                default_security_mode: SecurityMode::EncryptedAndSigned,
                key_rotation_days: Some(30),
            },
            protocols: ProtocolsConfig {
                mil_std_1553: MilStd1553Config {
                    interface: "sim0".to_string(),
                    simulated: true,
                    remote_terminals: vec![1, 2, 3, 4, 5],
                },
                ethernet_ip: EthernetIpConfig {
                    bind_address: "0.0.0.0".to_string(),
                    port: 44818,
                    timeout_secs: default_timeout(),
                    idle_timeout_secs: default_idle_timeout(),
                },
            },
            translation_rules: vec![
                TranslationRule {
                    name: "mil-to-ethernet".to_string(),
                    source: ProtocolType::MilStd1553,
                    target: ProtocolType::EthernetIp,
                    priority: default_priority(),
                    filter: HashMap::new(), 
                    transform: Some(TransformType::Identity),
                    security_mode: SecurityMode::EncryptedAndSigned,
                },
                TranslationRule {
                    name: "ethernet-to-mil".to_string(),
                    source: ProtocolType::EthernetIp,
                    target: ProtocolType::MilStd1553,
                    priority: default_priority(),
                    filter: HashMap::new(),
                    transform: Some(TransformType::Identity),
                    security_mode: SecurityMode::EncryptedAndSigned,
                },
            ],
        }
    }
    
    /// Load configuration from the default location
    pub fn load() -> Result<Self> {
        if let Ok(path) = std::env::var("GATEWAY_CONFIG") {
            return Self::from_file(path);
        }
        
        let config_paths = [
            "config.yaml",
            "config.json",
            "config/config.yaml",
            "config/config.json",
            "/etc/secure-gateway/config.yaml",
            "/etc/secure-gateway/config.json",
        ];
        
        for path in &config_paths {
            if std::path::Path::new(path).exists() {
                return Self::from_file(path);
            }
        }
        
        info!("No configuration file found, using defaults");
        Ok(Self::default())
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Check that the default keys are defined
        if self.security.default_encryption_key.is_empty() {
            return Err(anyhow!("Default encryption key ID must be specified"));
        }
        
        if self.security.default_signing_key.is_empty() {
            return Err(anyhow!("Default signing key ID must be specified"));
        }
        
        // Validate MIL-STD-1553 configuration
        for rt in &self.protocols.mil_std_1553.remote_terminals {
            if *rt > 31 {
                return Err(anyhow!("Invalid MIL-STD-1553 remote terminal address: {} (must be 0-31)", rt));
            }
        }
        
        // Validate EtherNet/IP configuration
        if self.protocols.ethernet_ip.port == 0 {
            return Err(anyhow!("EtherNet/IP port must be non-zero"));
        }
        
        // Validate translation rules
        for rule in &self.translation_rules {
            if rule.name.is_empty() {
                return Err(anyhow!("Translation rule name must not be empty"));
            }
            
            // Verify that source and target protocols are different
            if rule.source == rule.target {
                return Err(anyhow!("Translation rule '{}' has same source and target protocol", rule.name));
            }
        }
        
        Ok(())
    }
    
    /// Get log level from configuration
    pub fn get_log_level(&self) -> log::LevelFilter {
        match self.general.log_level.to_lowercase().as_str() {
            "trace" => log::LevelFilter::Trace,
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            _ => log::LevelFilter::Info, // Default
        }
    }
    
    /// Get worker thread count
    pub fn get_worker_count(&self) -> usize {
        if self.general.workers == 0 {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(2) // Default to 2 threads if we can't determine
        } else {
            self.general.workers
        }
    }
    
    /// Get timeout for EtherNet/IP connections
    pub fn get_ethernet_ip_timeout(&self) -> Duration {
        Duration::from_secs(self.protocols.ethernet_ip.timeout_secs)
    }
    
    /// Get idle timeout for EtherNet/IP sessions
    pub fn get_ethernet_ip_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.protocols.ethernet_ip.idle_timeout_secs)
    }
} 