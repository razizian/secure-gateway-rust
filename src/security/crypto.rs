//! Cryptographic utilities for the security module
//!
//! This module provides encryption, decryption, signature generation
//! and verification functionality.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{
    Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::{rngs::OsRng, RngCore};

use crate::security::SecurityError;

/// ChaCha20Poly1305 key size in bytes
pub const CHACHA_KEY_SIZE: usize = 32;

/// Nonce size for ChaCha20Poly1305
pub const NONCE_SIZE: usize = 12;

/// Ed25519 signature size
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 public key size
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Encrypt a message using ChaCha20Poly1305
pub fn encrypt_message(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != CHACHA_KEY_SIZE {
        return Err(anyhow!(SecurityError::EncryptionFailed(
            format!("Invalid key size: {} (expected {})", key.len(), CHACHA_KEY_SIZE)
        )));
    }
    
    // Create cipher instance
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| SecurityError::EncryptionFailed(e.to_string()))?;
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SecurityError::EncryptionFailed(e.to_string()))?;
    
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypt a message using ChaCha20Poly1305
pub fn decrypt_message(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != CHACHA_KEY_SIZE {
        return Err(anyhow!(SecurityError::DecryptionFailed(
            format!("Invalid key size: {} (expected {})", key.len(), CHACHA_KEY_SIZE)
        )));
    }
    
    if nonce_bytes.len() != NONCE_SIZE {
        return Err(anyhow!(SecurityError::DecryptionFailed(
            format!("Invalid nonce size: {} (expected {})", nonce_bytes.len(), NONCE_SIZE)
        )));
    }
    
    // Create cipher instance
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| SecurityError::DecryptionFailed(e.to_string()))?;
    
    // Create nonce
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| SecurityError::DecryptionFailed(e.to_string()))?;
    
    Ok(plaintext)
}

/// Sign a message using Ed25519
pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(anyhow!(SecurityError::AuthenticationFailed(
            format!("Invalid signing key size: {} (expected {})", 
                private_key.len(), ED25519_PRIVATE_KEY_SIZE)
        )));
    }
    
    // Create signing key
    let signing_key = SigningKey::from_bytes(
        &private_key.try_into()
            .map_err(|_| SecurityError::AuthenticationFailed("Invalid key format".into()))?
    );
    
    // Sign the message
    let signature = signing_key.sign(message);
    
    Ok(signature.to_bytes().to_vec())
}

/// Verify a signature using Ed25519
pub fn verify_signature(message: &[u8], signature_bytes: &[u8], public_key: &[u8]) -> Result<()> {
    if signature_bytes.len() != SIGNATURE_SIZE {
        return Err(anyhow!(SecurityError::AuthenticationFailed(
            format!("Invalid signature size: {} (expected {})", 
                signature_bytes.len(), SIGNATURE_SIZE)
        )));
    }
    
    if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
        return Err(anyhow!(SecurityError::AuthenticationFailed(
            format!("Invalid verification key size: {} (expected {})", 
                public_key.len(), ED25519_PUBLIC_KEY_SIZE)
        )));
    }
    
    // Create verification key
    let verifying_key = VerifyingKey::from_bytes(
        &public_key.try_into()
            .map_err(|_| SecurityError::AuthenticationFailed("Invalid key format".into()))?
    )
    .map_err(|e| SecurityError::AuthenticationFailed(e.to_string()))?;
    
    // Create signature object
    let signature = Signature::from_bytes(
        &signature_bytes.try_into()
            .map_err(|_| SecurityError::AuthenticationFailed("Invalid signature format".into()))?
    );
    
    // Verify signature
    verifying_key.verify(message, &signature)
        .map_err(|e| anyhow!(SecurityError::AuthenticationFailed(e.to_string())))
}

/// Generate a random encryption key
pub fn generate_encryption_key() -> [u8; CHACHA_KEY_SIZE] {
    let mut key = [0u8; CHACHA_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a new Ed25519 keypair
pub fn generate_signing_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate random bytes for private key
    let mut private_key_bytes = [0u8; ED25519_PRIVATE_KEY_SIZE];
    OsRng.fill_bytes(&mut private_key_bytes);
    
    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    
    // Get the verification key
    let verifying_key = VerifyingKey::from(&signing_key);
    
    // Return the keypair as bytes
    Ok((
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        // Generate a random key
        let key = generate_encryption_key();
        
        // Test message
        let message = b"This is a secret message for testing";
        
        // Encrypt
        let (ciphertext, nonce) = encrypt_message(message, &key).unwrap();
        
        // Make sure ciphertext is different from plaintext
        assert_ne!(ciphertext, message);
        
        // Decrypt
        let decrypted = decrypt_message(&ciphertext, &nonce, &key).unwrap();
        
        // Verify
        assert_eq!(decrypted, message);
        
        // Try with wrong key
        let wrong_key = generate_encryption_key();
        let result = decrypt_message(&ciphertext, &nonce, &wrong_key);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_sign_verify() {
        // Generate keypair
        let (private_key, public_key) = generate_signing_keypair().unwrap();
        
        // Test message
        let message = b"This message needs to be authenticated";
        
        // Sign
        let signature = sign_message(message, &private_key).unwrap();
        
        // Verify with correct key and message
        let result = verify_signature(message, &signature, &public_key);
        assert!(result.is_ok());
        
        // Try with tampered message
        let tampered = b"This message has been tampered with!";
        let result = verify_signature(tampered, &signature, &public_key);
        assert!(result.is_err());
        
        // Generate another keypair
        let (_, wrong_public_key) = generate_signing_keypair().unwrap();
        
        // Try with wrong public key
        let result = verify_signature(message, &signature, &wrong_public_key);
        assert!(result.is_err());
    }
} 