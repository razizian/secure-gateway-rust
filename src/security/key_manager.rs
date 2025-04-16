//! Key management system
//!
//! This module provides secure storage and management for cryptographic keys.

use anyhow::{anyhow, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::security::{SecurityError, crypto};

/// Key metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub id: String,
    pub key_type: KeyType,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub description: String,
}

/// Types of keys supported by the system
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Symmetric encryption key for ChaCha20Poly1305
    Encryption,
    
    /// Ed25519 signing key (private)
    Signing,
    
    /// Ed25519 verification key (public)
    Verification,
}

/// Key entry in the key store
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyEntry {
    pub metadata: KeyMetadata,
    pub key_data: Vec<u8>,
}

/// Manages cryptographic keys for the system
pub struct KeyManager {
    /// Storage for keys
    keys: Arc<RwLock<HashMap<String, KeyEntry>>>,
    
    /// Path to key storage file
    storage_path: Option<PathBuf>,
    
    /// Whether changes should be persisted to disk
    persistent: bool,
}

impl KeyManager {
    /// Create a new in-memory key manager (non-persistent)
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            storage_path: None,
            persistent: false,
        }
    }
    
    /// Create a persistent key manager that stores keys on disk
    pub fn new_persistent<P: AsRef<Path>>(path: P) -> Result<Self> {
        let storage_path = path.as_ref().to_path_buf();
        let keys = if storage_path.exists() {
            // Load existing keys from file
            let data = fs::read(&storage_path)
                .context("Failed to read key store file")?;
                
            // Deserialize the key store
            bincode::deserialize(&data)
                .context("Failed to deserialize key store")?
        } else {
            // Start with empty key store
            HashMap::new()
        };
        
        Ok(Self {
            keys: Arc::new(RwLock::new(keys)),
            storage_path: Some(storage_path),
            persistent: true,
        })
    }
    
    /// Save the key store to disk (if persistent)
    fn save(&self) -> Result<()> {
        if !self.persistent {
            return Ok(());
        }
        
        if let Some(path) = &self.storage_path {
            let keys = self.keys.read()
                .map_err(|_| anyhow!("Failed to acquire read lock on key store"))?;
                
            // Serialize the key store
            let data = bincode::serialize(&*keys)
                .context("Failed to serialize key store")?;
                
            // Create parent directory if it doesn't exist
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .context("Failed to create key store directory")?;
            }
            
            // Write to file
            fs::write(path, data)
                .context("Failed to write key store file")?;
        }
        
        Ok(())
    }
    
    /// Generate a new encryption key
    pub fn generate_encryption_key(&self, id: &str, description: &str, ttl_days: Option<u64>) -> Result<()> {
        // Generate random key
        let key_data = crypto::generate_encryption_key().to_vec();
        
        // Calculate expiration time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let expires_at = ttl_days.map(|days| {
            now + days * 24 * 60 * 60
        });
        
        // Create metadata
        let metadata = KeyMetadata {
            id: id.to_string(),
            key_type: KeyType::Encryption,
            created_at: now,
            expires_at,
            description: description.to_string(),
        };
        
        // Store the key
        let mut keys = self.keys.write()
            .map_err(|_| anyhow!("Failed to acquire write lock on key store"))?;
            
        keys.insert(id.to_string(), KeyEntry { metadata, key_data });
        
        // Save changes
        drop(keys);
        self.save()
    }
    
    /// Generate a new signing/verification key pair
    pub fn generate_keypair(&self, id: &str, description: &str, ttl_days: Option<u64>) -> Result<()> {
        // Generate Ed25519 keypair
        let (private_key, public_key) = crypto::generate_signing_keypair()?;
        
        // Calculate expiration time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let expires_at = ttl_days.map(|days| {
            now + days * 24 * 60 * 60
        });
        
        // Create metadata for signing key
        let signing_metadata = KeyMetadata {
            id: format!("{}-signing", id),
            key_type: KeyType::Signing,
            created_at: now,
            expires_at,
            description: format!("{} (signing)", description),
        };
        
        // Create metadata for verification key
        let verify_metadata = KeyMetadata {
            id: format!("{}-verify", id),
            key_type: KeyType::Verification,
            created_at: now,
            expires_at,
            description: format!("{} (verification)", description),
        };
        
        // Store the keys
        let mut keys = self.keys.write()
            .map_err(|_| anyhow!("Failed to acquire write lock on key store"))?;
            
        keys.insert(signing_metadata.id.clone(), 
            KeyEntry { metadata: signing_metadata, key_data: private_key });
            
        keys.insert(verify_metadata.id.clone(),
            KeyEntry { metadata: verify_metadata, key_data: public_key });
        
        // Save changes
        drop(keys);
        self.save()
    }
    
    /// Import an existing key
    pub fn import_key(&self, id: &str, key_type: KeyType, key_data: &[u8], 
                    description: &str, ttl_days: Option<u64>) -> Result<()> {
        // Validate key based on type
        match key_type {
            KeyType::Encryption => {
                if key_data.len() != crypto::CHACHA_KEY_SIZE {
                    return Err(anyhow!(SecurityError::KeyError(
                        format!("Invalid encryption key size: {} (expected {})",
                            key_data.len(), crypto::CHACHA_KEY_SIZE)
                    )));
                }
            },
            KeyType::Signing => {
                if key_data.len() != crypto::ED25519_PRIVATE_KEY_SIZE {
                    return Err(anyhow!(SecurityError::KeyError(
                        format!("Invalid signing key size: {} (expected {})",
                            key_data.len(), crypto::ED25519_PRIVATE_KEY_SIZE)
                    )));
                }
            },
            KeyType::Verification => {
                if key_data.len() != crypto::ED25519_PUBLIC_KEY_SIZE {
                    return Err(anyhow!(SecurityError::KeyError(
                        format!("Invalid verification key size: {} (expected {})",
                            key_data.len(), crypto::ED25519_PUBLIC_KEY_SIZE)
                    )));
                }
            },
        }
        
        // Calculate expiration time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let expires_at = ttl_days.map(|days| {
            now + days * 24 * 60 * 60
        });
        
        // Create metadata
        let metadata = KeyMetadata {
            id: id.to_string(),
            key_type,
            created_at: now,
            expires_at,
            description: description.to_string(),
        };
        
        // Store the key
        let mut keys = self.keys.write()
            .map_err(|_| anyhow!("Failed to acquire write lock on key store"))?;
            
        keys.insert(id.to_string(), KeyEntry { 
            metadata, 
            key_data: key_data.to_vec(),
        });
        
        // Save changes
        drop(keys);
        self.save()
    }
    
    /// Get an encryption key by ID
    pub fn get_encryption_key(&self, id: &str) -> Result<Vec<u8>> {
        let keys = self.keys.read()
            .map_err(|_| anyhow!("Failed to acquire read lock on key store"))?;
            
        let entry = keys.get(id)
            .ok_or_else(|| SecurityError::KeyError(format!("Key not found: {}", id)))?;
            
        if entry.metadata.key_type != KeyType::Encryption {
            return Err(anyhow!(SecurityError::KeyError(
                format!("Key {} is not an encryption key", id)
            )));
        }
        
        // Check if key is expired
        if let Some(expires_at) = entry.metadata.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
                
            if now > expires_at {
                return Err(anyhow!(SecurityError::KeyError(
                    format!("Key {} has expired", id)
                )));
            }
        }
        
        Ok(entry.key_data.clone())
    }
    
    /// Get a signing key by ID
    pub fn get_signing_key(&self, id: &str) -> Result<Vec<u8>> {
        let keys = self.keys.read()
            .map_err(|_| anyhow!("Failed to acquire read lock on key store"))?;
            
        let entry = keys.get(id)
            .ok_or_else(|| SecurityError::KeyError(format!("Key not found: {}", id)))?;
            
        if entry.metadata.key_type != KeyType::Signing {
            return Err(anyhow!(SecurityError::KeyError(
                format!("Key {} is not a signing key", id)
            )));
        }
        
        // Check if key is expired
        if let Some(expires_at) = entry.metadata.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
                
            if now > expires_at {
                return Err(anyhow!(SecurityError::KeyError(
                    format!("Key {} has expired", id)
                )));
            }
        }
        
        Ok(entry.key_data.clone())
    }
    
    /// Get a verification key by ID
    pub fn get_verification_key(&self, id: &str) -> Result<Vec<u8>> {
        let keys = self.keys.read()
            .map_err(|_| anyhow!("Failed to acquire read lock on key store"))?;
            
        let entry = keys.get(id)
            .ok_or_else(|| SecurityError::KeyError(format!("Key not found: {}", id)))?;
            
        if entry.metadata.key_type != KeyType::Verification {
            return Err(anyhow!(SecurityError::KeyError(
                format!("Key {} is not a verification key", id)
            )));
        }
        
        // Check if key is expired
        if let Some(expires_at) = entry.metadata.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
                
            if now > expires_at {
                return Err(anyhow!(SecurityError::KeyError(
                    format!("Key {} has expired", id)
                )));
            }
        }
        
        Ok(entry.key_data.clone())
    }
    
    /// List all keys
    pub fn list_keys(&self) -> Result<Vec<KeyMetadata>> {
        let keys = self.keys.read()
            .map_err(|_| anyhow!("Failed to acquire read lock on key store"))?;
            
        let metadata: Vec<KeyMetadata> = keys.values()
            .map(|entry| entry.metadata.clone())
            .collect();
            
        Ok(metadata)
    }
    
    /// Delete a key by ID
    pub fn delete_key(&self, id: &str) -> Result<()> {
        let mut keys = self.keys.write()
            .map_err(|_| anyhow!("Failed to acquire write lock on key store"))?;
            
        if keys.remove(id).is_none() {
            return Err(anyhow!(SecurityError::KeyError(
                format!("Key not found: {}", id)
            )));
        }
        
        // Save changes
        drop(keys);
        self.save()
    }
    
    /// Rotate an encryption key (generate new key and optionally delete old one)
    pub fn rotate_encryption_key(&self, old_id: &str, new_id: &str, 
                               description: &str, ttl_days: Option<u64>, 
                               delete_old: bool) -> Result<()> {
        // First generate the new key
        self.generate_encryption_key(new_id, description, ttl_days)?;
        
        // If requested, delete the old key
        if delete_old {
            self.delete_key(old_id)?;
        }
        
        Ok(())
    }
    
    /// Rotate a keypair (generate new pair and optionally delete old one)
    pub fn rotate_keypair(&self, old_id: &str, new_id: &str,
                        description: &str, ttl_days: Option<u64>,
                        delete_old: bool) -> Result<()> {
        // First generate the new keypair
        self.generate_keypair(new_id, description, ttl_days)?;
        
        // If requested, delete the old keypair
        if delete_old {
            // Delete both signing and verification keys
            let old_signing_id = format!("{}-signing", old_id);
            let old_verify_id = format!("{}-verify", old_id);
            
            let _ = self.delete_key(&old_signing_id);
            let _ = self.delete_key(&old_verify_id);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_key_generation() {
        let km = KeyManager::new();
        
        // Generate encryption key
        km.generate_encryption_key("test-enc", "Test encryption key", None).unwrap();
        
        // Generate keypair
        km.generate_keypair("test-pair", "Test keypair", None).unwrap();
        
        // Retrieve keys
        let enc_key = km.get_encryption_key("test-enc").unwrap();
        assert_eq!(enc_key.len(), crypto::CHACHA_KEY_SIZE);
        
        let signing_key = km.get_signing_key("test-pair-signing").unwrap();
        assert_eq!(signing_key.len(), crypto::ED25519_PRIVATE_KEY_SIZE);
        
        let verify_key = km.get_verification_key("test-pair-verify").unwrap();
        assert_eq!(verify_key.len(), crypto::ED25519_PUBLIC_KEY_SIZE);
        
        // List keys
        let keys = km.list_keys().unwrap();
        assert_eq!(keys.len(), 3); // 1 encryption key + 2 for the keypair
    }
    
    #[test]
    fn test_key_rotation() {
        let km = KeyManager::new();
        
        // Generate initial keys
        km.generate_encryption_key("enc-v1", "Encryption key v1", None).unwrap();
        km.generate_keypair("pair-v1", "Keypair v1", None).unwrap();
        
        // Rotate keys
        km.rotate_encryption_key("enc-v1", "enc-v2", "Encryption key v2", None, false).unwrap();
        km.rotate_keypair("pair-v1", "pair-v2", "Keypair v2", None, false).unwrap();
        
        // Check both old and new keys exist
        assert!(km.get_encryption_key("enc-v1").is_ok());
        assert!(km.get_encryption_key("enc-v2").is_ok());
        
        assert!(km.get_signing_key("pair-v1-signing").is_ok());
        assert!(km.get_signing_key("pair-v2-signing").is_ok());
        
        // Rotate again with deletion
        km.rotate_encryption_key("enc-v2", "enc-v3", "Encryption key v3", None, true).unwrap();
        km.rotate_keypair("pair-v2", "pair-v3", "Keypair v3", None, true).unwrap();
        
        // Check v2 is gone but v3 exists
        assert!(km.get_encryption_key("enc-v2").is_err());
        assert!(km.get_encryption_key("enc-v3").is_ok());
        
        assert!(km.get_signing_key("pair-v2-signing").is_err());
        assert!(km.get_signing_key("pair-v3-signing").is_ok());
        
        // Original v1 should still exist
        assert!(km.get_encryption_key("enc-v1").is_ok());
        assert!(km.get_signing_key("pair-v1-signing").is_ok());
    }
    
    #[test]
    fn test_persistence() {
        // Create temporary directory for key storage
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.bin");
        
        // Create key manager and add some keys
        {
            let km = KeyManager::new_persistent(&path).unwrap();
            km.generate_encryption_key("test-enc", "Test encryption key", None).unwrap();
            km.generate_keypair("test-pair", "Test keypair", None).unwrap();
        }
        
        // Create new instance and verify keys were loaded
        {
            let km = KeyManager::new_persistent(&path).unwrap();
            
            let enc_key = km.get_encryption_key("test-enc").unwrap();
            assert_eq!(enc_key.len(), crypto::CHACHA_KEY_SIZE);
            
            let signing_key = km.get_signing_key("test-pair-signing").unwrap();
            assert_eq!(signing_key.len(), crypto::ED25519_PRIVATE_KEY_SIZE);
        }
    }
    
    #[test]
    fn test_key_expiration() {
        let km = KeyManager::new();
        
        // Generate key that expired in the past
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        // Create metadata with past expiration
        let metadata = KeyMetadata {
            id: "expired-key".to_string(),
            key_type: KeyType::Encryption,
            created_at: now - 100,
            expires_at: Some(now - 10),
            description: "Expired key".to_string(),
        };
        
        // Create random key data
        let mut key_data = vec![0u8; crypto::CHACHA_KEY_SIZE];
        OsRng.fill_bytes(&mut key_data);
        
        // Add expired key
        {
            let mut keys = km.keys.write().unwrap();
            keys.insert("expired-key".to_string(), KeyEntry { metadata, key_data });
        }
        
        // Attempt to retrieve the expired key should fail
        let result = km.get_encryption_key("expired-key");
        assert!(result.is_err());
        
        // Generate non-expiring key
        km.generate_encryption_key("non-expiring", "Non-expiring key", None).unwrap();
        
        // This should succeed
        let key = km.get_encryption_key("non-expiring");
        assert!(key.is_ok());
    }
} 