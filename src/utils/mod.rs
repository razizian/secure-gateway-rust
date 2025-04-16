//! Utility functions for the secure gateway
//!
//! This module provides various helper functions and utilities
//! used throughout the application.

use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp in milliseconds
pub fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Convert bytes to a hexadecimal string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{:02x}", b));
            acc
        })
}

/// Parse a hexadecimal string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i+2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex character: {}", e))?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Create a unique ID for messages
pub fn generate_unique_id() -> u64 {
    // Combine timestamp with a randomized part
    let timestamp = current_time_millis();
    let random_part = rand::random::<u16>() as u64;
    
    (timestamp << 16) | random_part
}

/// Format a byte size with appropriate unit
pub fn format_byte_size(size: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    
    if size == 0 {
        return "0 B".to_string();
    }
    
    let size_f64 = size as f64;
    let exp = (size_f64.ln() / 1024_f64.ln()).floor() as usize;
    let exp = exp.min(UNITS.len() - 1);
    
    let size = size_f64 / (1024_f64.powi(exp as i32));
    
    format!("{:.2} {}", size, UNITS[exp])
}

/// Check if a value is within range
pub fn is_in_range<T: PartialOrd>(value: T, min: T, max: T) -> bool {
    value >= min && value <= max
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0x12, 0x34, 0xAB, 0xCD];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "1234abcd");
    }
    
    #[test]
    fn test_hex_to_bytes() {
        let hex = "1234abcd";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34, 0xAB, 0xCD]);
    }
    
    #[test]
    fn test_hex_to_bytes_invalid() {
        let result = hex_to_bytes("123"); // Odd length
        assert!(result.is_err());
        
        let result = hex_to_bytes("123G"); // Invalid character
        assert!(result.is_err());
    }
    
    #[test]
    fn test_generate_unique_id() {
        let id1 = generate_unique_id();
        let id2 = generate_unique_id();
        assert_ne!(id1, id2); // Should generate different IDs
    }
    
    #[test]
    fn test_format_byte_size() {
        assert_eq!(format_byte_size(0), "0 B");
        assert_eq!(format_byte_size(1023), "1023.00 B");
        assert_eq!(format_byte_size(1024), "1.00 KB");
        assert_eq!(format_byte_size(1048576), "1.00 MB");
        assert_eq!(format_byte_size(1073741824), "1.00 GB");
    }
    
    #[test]
    fn test_is_in_range() {
        assert!(is_in_range(5, 1, 10));
        assert!(is_in_range(1, 1, 10));
        assert!(is_in_range(10, 1, 10));
        assert!(!is_in_range(0, 1, 10));
        assert!(!is_in_range(11, 1, 10));
        
        assert!(is_in_range(5.5, 1.0, 10.0));
        assert!(!is_in_range(10.1, 1.0, 10.0));
    }
} 