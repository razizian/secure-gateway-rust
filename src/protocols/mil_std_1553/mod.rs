//! MIL-STD-1553 protocol implementation
//!
//! This module contains types and functions for handling the MIL-STD-1553
//! military/aerospace communication standard.

mod parser;

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, warn};
use std::any::Any;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocols::{CommonMessage, Message, MessageMetadata, ProtocolHandler, ProtocolType};
use parser::parse_mil_std_1553;

/// Word type for MIL-STD-1553
#[derive(Debug, Clone, Copy)]
pub struct Word(u16);

impl Word {
    pub fn new(value: u16) -> Self {
        Word(value)
    }
    
    pub fn value(&self) -> u16 {
        self.0
    }
}

/// Types of MIL-STD-1553 words
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordType {
    Command,
    Status,
    Data,
}

/// Message types in MIL-STD-1553
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    BcToRt,     // Bus Controller to Remote Terminal
    RtToBc,     // Remote Terminal to Bus Controller
    RtToRt,     // Remote Terminal to Remote Terminal
    ModeCode,   // Mode Code Command
}

/// Represents a MIL-STD-1553 message
#[derive(Clone)]
pub struct Mil1553Message {
    pub message_type: MessageType,
    pub command_word: Word,
    pub status_word: Option<Word>,
    pub data_words: Vec<Word>,
    pub timestamp: u64,
    pub remote_terminal_address: u8,
    pub subaddress: u8,
    pub word_count: u8,
}

impl Mil1553Message {
    pub fn new(
        message_type: MessageType,
        command_word: Word,
        status_word: Option<Word>,
        data_words: Vec<Word>,
    ) -> Self {
        // Extract fields from command word
        let cmd = command_word.value();
        let remote_terminal_address = ((cmd >> 11) & 0x1F) as u8;
        let subaddress = ((cmd >> 5) & 0x1F) as u8;
        let word_count = (cmd & 0x1F) as u8;
        
        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
            
        Self {
            message_type,
            command_word,
            status_word,
            data_words,
            timestamp,
            remote_terminal_address,
            subaddress,
            word_count,
        }
    }
    
    // Convert to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(
            2 + // Command word
            if self.status_word.is_some() { 2 } else { 0 } + // Status word (if present)
            self.data_words.len() * 2 // Data words
        );
        
        // Add command word
        buffer.put_u16(self.command_word.value());
        
        // Add status word if present
        if let Some(status) = self.status_word {
            buffer.put_u16(status.value());
        }
        
        // Add data words
        for word in &self.data_words {
            buffer.put_u16(word.value());
        }
        
        buffer.to_vec()
    }
    
    // Create a unique message ID
    fn generate_message_id(&self) -> u64 {
        // Combine timestamp with RT address and subaddress for uniqueness
        (self.timestamp << 16) | 
        ((self.remote_terminal_address as u64) << 8) | 
        (self.subaddress as u64)
    }
}

impl fmt::Debug for Mil1553Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mil1553Message {{ type: {:?}, RT: {}, subaddr: {}, words: {} }}",
            self.message_type, self.remote_terminal_address, self.subaddress, self.data_words.len())
    }
}

impl Message for Mil1553Message {
    fn to_common_format(&self) -> Result<CommonMessage> {
        // Create source and destination addresses
        let source_addr = match self.message_type {
            MessageType::BcToRt | MessageType::ModeCode => "BC".to_string(),
            MessageType::RtToBc => format!("RT{}", self.remote_terminal_address),
            MessageType::RtToRt => {
                // For RT to RT, source is in the status word
                if let Some(status) = self.status_word {
                    let src_rt = ((status.value() >> 11) & 0x1F) as u8;
                    format!("RT{}", src_rt)
                } else {
                    "UNKNOWN".to_string()
                }
            }
        };
        
        let dest_addr = match self.message_type {
            MessageType::BcToRt | MessageType::ModeCode => 
                format!("RT{}", self.remote_terminal_address),
            MessageType::RtToBc => "BC".to_string(),
            MessageType::RtToRt => format!("RT{}", self.remote_terminal_address),
        };
        
        // Prepare payload
        let mut payload = Vec::new();
        for word in &self.data_words {
            payload.extend_from_slice(&word.value().to_be_bytes());
        }
        
        // Create message metadata
        let metadata = MessageMetadata {
            source_address: source_addr,
            destination_address: dest_addr,
            timestamp: self.timestamp,
            message_id: self.generate_message_id(),
            is_command: matches!(self.message_type, MessageType::BcToRt | MessageType::ModeCode),
            requires_response: self.message_type != MessageType::RtToBc,
        };
        
        // Create common message
        Ok(CommonMessage {
            source_protocol: ProtocolType::MilStd1553,
            target_protocol: Some(ProtocolType::EthernetIp),  // Default translation target
            priority: 2,  // Medium priority by default
            payload,
            metadata,
        })
    }
    
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::MilStd1553
    }
    
    fn clone_box(&self) -> Box<dyn Message> {
        Box::new(self.clone())
    }
    
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Handler for MIL-STD-1553 protocol
pub struct Mil1553Handler {
    // Configuration for the handler could go here
}

impl Mil1553Handler {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProtocolHandler for Mil1553Handler {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn Message>> {
        parse_mil_std_1553(data)
            .context("Failed to parse MIL-STD-1553 message")
            .map(|msg| Box::new(msg) as Box<dyn Message>)
    }
    
    fn format(&self, message: &CommonMessage) -> Result<Vec<u8>> {
        // Create a simplified 1553 message from the common format
        let rt_addr = message.metadata.destination_address
            .strip_prefix("RT")
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(1);  // Default to RT1 if parsing fails
            
        let subaddress = 1; // Use a default subaddress
        
        // Create data words from payload
        let mut data_words = Vec::new();
        let chunks = message.payload.chunks_exact(2);
        
        // Handle any remaining odd byte
        let remainder = chunks.remainder();
        
        for chunk in chunks {
            let value = u16::from_be_bytes([chunk[0], chunk[1]]);
            data_words.push(Word::new(value));
        }
        
        // Handle odd byte if present
        if !remainder.is_empty() {
            let value = u16::from_be_bytes([remainder[0], 0]);
            data_words.push(Word::new(value));
        }
        
        // Ensure word count is valid (1-32)
        let word_count = data_words.len().min(32) as u8;
        
        // Construct command word: [RT addr(5)][T/R(1)][subaddr(5)][word count(5)]
        // T/R bit: 1 for RT->BC (receive), 0 for BC->RT (transmit)
        let t_r_bit = if message.metadata.source_address.starts_with("RT") { 1 } else { 0 };
        let command_word = Word::new(
            ((rt_addr as u16) << 11) | 
            ((t_r_bit as u16) << 10) | 
            ((subaddress as u16) << 5) | 
            (word_count as u16)
        );
        
        let message_type = if t_r_bit == 1 {
            MessageType::RtToBc
        } else {
            MessageType::BcToRt
        };
        
        // Create 1553 message
        let mil_message = Mil1553Message::new(
            message_type,
            command_word,
            None,  // No status word for outgoing messages
            data_words,
        );
        
        Ok(mil_message.to_bytes())
    }
    
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::MilStd1553
    }
} 