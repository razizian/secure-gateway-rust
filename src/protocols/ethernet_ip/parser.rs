//! Ethernet/IP protocol parser
//!
//! This module contains functions for parsing raw bytes into
//! Ethernet/IP packet structures.

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, Bytes};
use log::debug;

use super::{CommandType, EthernetIpPacket};

/// Parse Ethernet/IP packet from raw bytes
pub fn parse_ethernet_ip(data: &[u8]) -> Result<EthernetIpPacket> {
    if data.len() < 24 {
        bail!("Data too short for Ethernet/IP packet, minimum is 24 bytes");
    }
    
    let mut bytes = Bytes::copy_from_slice(data);
    
    // Parse header
    let command = CommandType::from_u8(bytes.get_u8());
    let _reserved = bytes.get_u8(); // Skip reserved byte
    let length = bytes.get_u16() as usize;
    
    // Verify packet length
    if length != data.len() {
        debug!("Length field ({}) doesn't match data length ({})", length, data.len());
        // Continue anyway, as real-world packets might have this mismatch
    }
    
    let session_handle = bytes.get_u32();
    let status = bytes.get_u32();
    
    // Read sender context (8 bytes)
    let mut sender_context = [0u8; 8];
    bytes.copy_to_slice(&mut sender_context);
    
    let options = bytes.get_u32();
    
    // Remaining bytes are the data portion
    let data = bytes.to_vec();
    
    // Create packet with placeholder addresses - in real implementation,
    // these would come from network layer information
    let packet = EthernetIpPacket::new(
        command,
        session_handle,
        status,
        sender_context,
        options,
        data,
        "192.168.1.100".to_string(), // Example source IP
        "192.168.1.200".to_string(), // Example destination IP
    );
    
    debug!("Parsed Ethernet/IP packet: {:?}", packet);
    Ok(packet)
}

/// Validate Ethernet/IP packet
pub fn validate_ethernet_ip(data: &[u8]) -> bool {
    if data.len() < 24 {
        return false;
    }
    
    let mut bytes = Bytes::copy_from_slice(data);
    
    // Check command byte (first byte)
    let command = bytes.get_u8();
    match command {
        0x63 | 0x64 | 0x65 | 0x66 | 0x6F | 0x70 | 0x0A | 0x0B => {},
        _ => return false, // Invalid command
    }
    
    // Skip reserved byte
    bytes.advance(1);
    
    // Check length field (should be reasonable)
    let length = bytes.get_u16() as usize;
    if length < 24 || length > 1500 { // 1500 is typical MTU
        return false;
    }
    
    // If we get here, packet structure is likely valid
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_ethernet_ip() {
        // Create a sample packet
        let mut data = Vec::new();
        
        // Command
        data.push(0x6F); // SendRRData
        
        // Reserved
        data.push(0);
        
        // Length (header + data length)
        let length: u16 = 24 + 4; // Header + 4 bytes of data
        data.extend_from_slice(&length.to_be_bytes());
        
        // Session handle
        let session: u32 = 0x12345678;
        data.extend_from_slice(&session.to_be_bytes());
        
        // Status
        let status: u32 = 0;
        data.extend_from_slice(&status.to_be_bytes());
        
        // Sender context (8 bytes)
        data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        
        // Options
        let options: u32 = 0;
        data.extend_from_slice(&options.to_be_bytes());
        
        // Data (4 bytes)
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        
        // Parse the packet
        let packet = parse_ethernet_ip(&data).unwrap();
        
        // Verify fields
        assert_eq!(packet.command, CommandType::SendRRData);
        assert_eq!(packet.session_handle, 0x12345678);
        assert_eq!(packet.status, 0);
        assert_eq!(packet.sender_context, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(packet.options, 0);
        assert_eq!(packet.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
    
    #[test]
    fn test_validate_ethernet_ip() {
        // Valid packet
        let mut valid_data = Vec::new();
        valid_data.push(0x6F); // Command
        valid_data.push(0);    // Reserved
        valid_data.extend_from_slice(&(24u16).to_be_bytes()); // Length
        valid_data.extend_from_slice(&[0; 20]); // Rest of header
        
        assert!(validate_ethernet_ip(&valid_data));
        
        // Invalid command
        let mut invalid_cmd = valid_data.clone();
        invalid_cmd[0] = 0xFF; // Invalid command
        assert!(!validate_ethernet_ip(&invalid_cmd));
        
        // Invalid length
        let mut invalid_len = valid_data.clone();
        invalid_len[2..4].copy_from_slice(&(10u16).to_be_bytes()); // Too small
        assert!(!validate_ethernet_ip(&invalid_len));
        
        // Too short data
        let short_data = vec![0; 10];
        assert!(!validate_ethernet_ip(&short_data));
    }
} 