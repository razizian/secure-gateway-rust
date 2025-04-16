//! Ethernet/IP protocol implementation
//!
//! This module contains types and functions for handling Ethernet/IP
//! industrial protocol communications.

mod parser;

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::debug;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocols::{CommonMessage, Message, MessageMetadata, ProtocolHandler, ProtocolType};
use parser::parse_ethernet_ip;

/// EtherNet/IP command types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CommandType {
    ListIdentity = 0x63,
    ListServices = 0x64,
    ListInterfaces = 0x65,
    RegisterSession = 0x66,
    UnregisterSession = 0x67,
    SendRRData = 0x6F,
    SendUnitData = 0x70,
    DataRequest = 0x0A,
    DataResponse = 0x0B,
    Custom(u8),
}

impl CommandType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x63 => CommandType::ListIdentity,
            0x64 => CommandType::ListServices,
            0x65 => CommandType::ListInterfaces,
            0x66 => CommandType::RegisterSession,
            0x67 => CommandType::UnregisterSession,
            0x6F => CommandType::SendRRData,
            0x70 => CommandType::SendUnitData,
            0x0A => CommandType::DataRequest,
            0x0B => CommandType::DataResponse,
            _ => CommandType::Custom(value),
        }
    }
    
    pub fn as_u8(&self) -> u8 {
        match self {
            CommandType::ListIdentity => 0x63,
            CommandType::ListServices => 0x64,
            CommandType::ListInterfaces => 0x65,
            CommandType::RegisterSession => 0x66,
            CommandType::UnregisterSession => 0x67,
            CommandType::SendRRData => 0x6F,
            CommandType::SendUnitData => 0x70,
            CommandType::DataRequest => 0x0A,
            CommandType::DataResponse => 0x0B,
            CommandType::Custom(value) => *value,
        }
    }
}

/// EtherNet/IP packet structure
#[derive(Clone, Serialize, Deserialize)]
pub struct EthernetIpPacket {
    pub command: CommandType,
    pub session_handle: u32,
    pub status: u32,
    pub sender_context: [u8; 8],
    pub options: u32,
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub source_address: String,
    pub destination_address: String,
}

impl EthernetIpPacket {
    pub fn new(
        command: CommandType,
        session_handle: u32,
        status: u32,
        sender_context: [u8; 8],
        options: u32,
        data: Vec<u8>,
        source_address: String,
        destination_address: String,
    ) -> Self {
        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
            
        Self {
            command,
            session_handle,
            status,
            sender_context,
            options,
            data,
            timestamp,
            source_address,
            destination_address,
        }
    }
    
    /// Convert packet to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(24 + self.data.len());
        
        // Command (1 byte)
        buffer.put_u8(self.command.as_u8());
        
        // Reserved (1 byte)
        buffer.put_u8(0);
        
        // Length (2 bytes) - header (24 bytes) + data
        buffer.put_u16((24 + self.data.len()) as u16);
        
        // Session handle (4 bytes)
        buffer.put_u32(self.session_handle);
        
        // Status (4 bytes)
        buffer.put_u32(self.status);
        
        // Sender context (8 bytes)
        buffer.put_slice(&self.sender_context);
        
        // Options (4 bytes)
        buffer.put_u32(self.options);
        
        // Data
        buffer.put_slice(&self.data);
        
        buffer.to_vec()
    }
    
    // Generate a unique message ID
    fn generate_message_id(&self) -> u64 {
        // Combine timestamp with session handle for uniqueness
        (self.timestamp << 32) | (self.session_handle as u64)
    }
}

impl fmt::Debug for EthernetIpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EthernetIpPacket {{ command: {:?}, session: 0x{:X}, src: {}, dst: {}, data_len: {} }}",
            self.command, self.session_handle, self.source_address, self.destination_address, self.data.len())
    }
}

impl Message for EthernetIpPacket {
    fn to_common_format(&self) -> Result<CommonMessage> {
        // Determine if this is a command based on the command type
        let is_command = matches!(
            self.command,
            CommandType::ListIdentity | 
            CommandType::ListServices |
            CommandType::RegisterSession |
            CommandType::SendRRData |
            CommandType::DataRequest
        );
        
        // Determine if a response is expected
        let requires_response = is_command && !matches!(
            self.command, 
            CommandType::UnregisterSession |
            CommandType::SendUnitData
        );
        
        // Create message metadata
        let metadata = MessageMetadata {
            source_address: self.source_address.clone(),
            destination_address: self.destination_address.clone(),
            timestamp: self.timestamp,
            message_id: self.generate_message_id(),
            is_command,
            requires_response,
        };
        
        // Create common message
        Ok(CommonMessage {
            source_protocol: ProtocolType::EthernetIp,
            target_protocol: Some(ProtocolType::MilStd1553), // Default translation target
            priority: if is_command { 1 } else { 3 },  // Higher priority for commands
            payload: self.data.clone(),
            metadata,
        })
    }
    
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::EthernetIp
    }
    
    fn clone_box(&self) -> Box<dyn Message> {
        Box::new(self.clone())
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Handler for Ethernet/IP protocol
pub struct EthernetIpHandler {
    // Configuration could go here
    session_counter: u32,
}

impl EthernetIpHandler {
    pub fn new() -> Self {
        Self {
            session_counter: 1,
        }
    }
    
    // Generate a new session handle
    fn next_session(&mut self) -> u32 {
        let session = self.session_counter;
        self.session_counter += 1;
        if self.session_counter == 0 {
            self.session_counter = 1; // Never use 0 as a session handle
        }
        session
    }
}

impl ProtocolHandler for EthernetIpHandler {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn Message>> {
        parse_ethernet_ip(data)
            .context("Failed to parse Ethernet/IP message")
            .map(|msg| Box::new(msg) as Box<dyn Message>)
    }
    
    fn format(&self, message: &CommonMessage) -> Result<Vec<u8>> {
        // Create an Ethernet/IP packet from the common format
        
        // Determine appropriate command type based on message metadata
        let command = if message.metadata.is_command {
            if message.metadata.requires_response {
                CommandType::SendRRData
            } else {
                CommandType::SendUnitData
            }
        } else {
            CommandType::DataResponse
        };
        
        // Create sender context (8 bytes of zeroes for simplicity)
        let sender_context = [0u8; 8];
        
        // Create packet
        let packet = EthernetIpPacket::new(
            command,
            0x01020304, // Example session handle
            0,          // Status (0 = success)
            sender_context,
            0,          // Options (0 = no options)
            message.payload.clone(),
            message.metadata.source_address.clone(),
            message.metadata.destination_address.clone(),
        );
        
        Ok(packet.to_bytes())
    }
    
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::EthernetIp
    }
} 