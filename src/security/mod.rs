//! Security components for the gateway
//!
//! This module provides cryptographic services such as encryption,
//! authentication, and key management.

pub mod key_manager;
pub mod crypto;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use key_manager::KeyManager;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Key error: {0}")]
    KeyError(String),
    
    #[error("Invalid security configuration: {0}")]
    ConfigError(String),
}

/// Represents the security mode for a message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityMode {
    /// No security applied
    None,
    
    /// Message is signed but not encrypted
    Signed,
    
    /// Message is encrypted but not signed
    Encrypted,
    
    /// Message is both encrypted and signed
    EncryptedAndSigned,
}

impl Default for SecurityMode {
    fn default() -> Self {
        SecurityMode::EncryptedAndSigned
    }
}

/// Header for secured messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeader {
    pub version: u8,
    pub mode: SecurityMode,
    pub key_id: String,
    pub nonce: Vec<u8>,  // For ChaCha20Poly1305
    pub signature: Option<Vec<u8>>,  // For Ed25519 signatures
}

/// Secured message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuredMessage {
    pub header: SecurityHeader,
    pub payload: Vec<u8>,
    pub hmac: Option<Vec<u8>>,  // Message authentication code
}

/// Security service for message protection
pub struct SecurityService {
    key_manager: KeyManager,
}

impl SecurityService {
    pub fn new(key_manager: KeyManager) -> Self {
        Self { key_manager }
    }
    
    /// Secure a message with appropriate encryption and/or signatures
    pub fn secure_message(&self, data: &[u8], mode: SecurityMode, key_id: &str) -> Result<SecuredMessage> {
        match mode {
            SecurityMode::None => {
                // No security, just wrap in our format
                Ok(SecuredMessage {
                    header: SecurityHeader {
                        version: 1,
                        mode,
                        key_id: key_id.to_string(),
                        nonce: vec![],
                        signature: None,
                    },
                    payload: data.to_vec(),
                    hmac: None,
                })
            },
            
            SecurityMode::Signed => {
                // Sign the message with Ed25519
                let signature = crypto::sign_message(data, &self.key_manager.get_signing_key(key_id)?)?;
                
                Ok(SecuredMessage {
                    header: SecurityHeader {
                        version: 1,
                        mode,
                        key_id: key_id.to_string(),
                        nonce: vec![],
                        signature: Some(signature),
                    },
                    payload: data.to_vec(),
                    hmac: None,
                })
            },
            
            SecurityMode::Encrypted => {
                // Encrypt the message with ChaCha20Poly1305
                let (ciphertext, nonce) = crypto::encrypt_message(
                    data, 
                    &self.key_manager.get_encryption_key(key_id)?
                )?;
                
                Ok(SecuredMessage {
                    header: SecurityHeader {
                        version: 1,
                        mode,
                        key_id: key_id.to_string(),
                        nonce,
                        signature: None,
                    },
                    payload: ciphertext,
                    hmac: None,
                })
            },
            
            SecurityMode::EncryptedAndSigned => {
                // First sign the plaintext
                let signature = crypto::sign_message(data, &self.key_manager.get_signing_key(key_id)?)?;
                
                // Then encrypt the plaintext (not the signature)
                let (ciphertext, nonce) = crypto::encrypt_message(
                    data, 
                    &self.key_manager.get_encryption_key(key_id)?
                )?;
                
                Ok(SecuredMessage {
                    header: SecurityHeader {
                        version: 1,
                        mode,
                        key_id: key_id.to_string(),
                        nonce,
                        signature: Some(signature),
                    },
                    payload: ciphertext,
                    hmac: None,
                })
            },
        }
    }
    
    /// Extract the original message from a secured message
    pub fn extract_message(&self, secured: &SecuredMessage) -> Result<Vec<u8>> {
        match secured.header.mode {
            SecurityMode::None => {
                // No security, just return the payload
                Ok(secured.payload.clone())
            },
            
            SecurityMode::Signed => {
                // Verify the signature
                let signature = secured.header.signature.as_ref()
                    .ok_or_else(|| SecurityError::AuthenticationFailed("Missing signature".into()))?;
                
                // Verify using the public key
                crypto::verify_signature(
                    &secured.payload, 
                    signature, 
                    &self.key_manager.get_verification_key(&secured.header.key_id)?
                )?;
                
                Ok(secured.payload.clone())
            },
            
            SecurityMode::Encrypted => {
                // Decrypt the payload
                crypto::decrypt_message(
                    &secured.payload, 
                    &secured.header.nonce, 
                    &self.key_manager.get_encryption_key(&secured.header.key_id)?
                )
            },
            
            SecurityMode::EncryptedAndSigned => {
                // First decrypt the payload
                let plaintext = crypto::decrypt_message(
                    &secured.payload, 
                    &secured.header.nonce, 
                    &self.key_manager.get_encryption_key(&secured.header.key_id)?
                )?;
                
                // Then verify the signature on the decrypted plaintext
                let signature = secured.header.signature.as_ref()
                    .ok_or_else(|| SecurityError::AuthenticationFailed("Missing signature".into()))?;
                
                crypto::verify_signature(
                    &plaintext, 
                    signature, 
                    &self.key_manager.get_verification_key(&secured.header.key_id)?
                )?;
                
                Ok(plaintext)
            },
        }
    }
    
    /// Serialize a secured message to bytes
    pub fn serialize(&self, message: &SecuredMessage) -> Result<Vec<u8>> {
        bincode::serialize(message)
            .map_err(|e| anyhow::anyhow!("Failed to serialize secured message: {}", e))
    }
    
    /// Deserialize bytes to a secured message
    pub fn deserialize(&self, data: &[u8]) -> Result<SecuredMessage> {
        bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize secured message: {}", e))
    }
} 