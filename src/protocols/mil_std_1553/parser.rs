//! MIL-STD-1553 message parser
//! 
//! This module contains functions for parsing raw bytes into
//! MIL-STD-1553 message structures.

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, Bytes};
use log::debug;
use nom::{
    bytes::complete::take,
    combinator::{map, verify},
    number::complete::{be_u16, be_u8},
    sequence::tuple,
    IResult,
};

use super::{MessageType, Mil1553Message, Word};

/// Parse a MIL-STD-1553 message from raw bytes
pub fn parse_mil_std_1553(data: &[u8]) -> Result<Mil1553Message> {
    if data.len() < 2 {
        bail!("Data too short for MIL-STD-1553 message");
    }
    
    let mut bytes = Bytes::copy_from_slice(data);
    
    // Read command word
    let command_word = Word::new(bytes.get_u16());
    
    // Extract fields from command word
    let cmd = command_word.value();
    let rt_addr = ((cmd >> 11) & 0x1F) as u8;
    let tr_bit = ((cmd >> 10) & 0x1) as u8;
    let subaddress = ((cmd >> 5) & 0x1F) as u8;
    let word_count = (cmd & 0x1F) as u8;
    
    // Determine message type based on command word
    let message_type = if subaddress == 0 {
        MessageType::ModeCode
    } else if tr_bit == 0 {
        MessageType::BcToRt
    } else {
        MessageType::RtToBc
    };
    
    // Read status word if present (typically in responses)
    let mut status_word = None;
    if bytes.remaining() >= 2 && (message_type == MessageType::RtToBc) {
        status_word = Some(Word::new(bytes.get_u16()));
    }
    
    // Read data words
    let mut data_words = Vec::new();
    while bytes.remaining() >= 2 && data_words.len() < 32 {
        data_words.push(Word::new(bytes.get_u16()));
    }
    
    // Create message
    let message = Mil1553Message::new(
        message_type,
        command_word,
        status_word,
        data_words,
    );
    
    debug!("Parsed MIL-STD-1553 message: {:?}", message);
    Ok(message)
}

/// Validate a command word
fn validate_command_word(word: u16) -> bool {
    // RT address should be 0-31
    let rt_addr = (word >> 11) & 0x1F;
    
    // Subaddress should be 0-31
    let subaddr = (word >> 5) & 0x1F;
    
    // Word count should be 1-32 (represented as 0-31)
    let word_count = word & 0x1F;
    
    // Broadcast is a special case (RT address 31)
    let is_broadcast = rt_addr == 0x1F;
    
    // Validate based on typical constraints
    rt_addr <= 0x1F && subaddr <= 0x1F && (word_count > 0 || is_broadcast)
}

/// Validate a status word
fn validate_status_word(word: u16) -> bool {
    // RT address should be 0-31
    let rt_addr = (word >> 11) & 0x1F;
    
    // Various status bits
    let message_error = (word >> 9) & 0x1;
    let instrumentation = (word >> 8) & 0x1;
    let service_request = (word >> 7) & 0x1;
    
    // Typically, certain bits should be 0 in normal operation
    rt_addr <= 0x1F && message_error == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_bc_to_rt() {
        // Command word: RT5, receive, subaddress 2, 3 data words
        // RT5 (5 << 11) | T/R=0 (0 << 10) | SA2 (2 << 5) | WC=3
        let command_word: u16 = (5 << 11) | (0 << 10) | (2 << 5) | 3;
        
        // Data words
        let data1: u16 = 0x1234;
        let data2: u16 = 0x5678;
        let data3: u16 = 0x9ABC;
        
        // Create message bytes
        let mut data = Vec::new();
        data.extend_from_slice(&command_word.to_be_bytes());
        data.extend_from_slice(&data1.to_be_bytes());
        data.extend_from_slice(&data2.to_be_bytes());
        data.extend_from_slice(&data3.to_be_bytes());
        
        // Parse message
        let message = parse_mil_std_1553(&data).unwrap();
        
        // Verify
        assert_eq!(message.message_type, MessageType::BcToRt);
        assert_eq!(message.remote_terminal_address, 5);
        assert_eq!(message.subaddress, 2);
        assert_eq!(message.word_count, 3);
        assert_eq!(message.data_words.len(), 3);
        assert_eq!(message.data_words[0].value(), data1);
        assert_eq!(message.data_words[1].value(), data2);
        assert_eq!(message.data_words[2].value(), data3);
    }
    
    #[test]
    fn test_parse_rt_to_bc() {
        // Command word: RT3, transmit, subaddress 7, 2 data words
        // RT3 (3 << 11) | T/R=1 (1 << 10) | SA7 (7 << 5) | WC=2
        let command_word: u16 = (3 << 11) | (1 << 10) | (7 << 5) | 2;
        
        // Status word (typically echoes the RT address)
        // RT3 (3 << 11) | remaining bits all 0 for simplicity
        let status_word: u16 = 3 << 11;
        
        // Data words
        let data1: u16 = 0x1234;
        let data2: u16 = 0x5678;
        
        // Create message bytes
        let mut data = Vec::new();
        data.extend_from_slice(&command_word.to_be_bytes());
        data.extend_from_slice(&status_word.to_be_bytes());
        data.extend_from_slice(&data1.to_be_bytes());
        data.extend_from_slice(&data2.to_be_bytes());
        
        // Parse message
        let message = parse_mil_std_1553(&data).unwrap();
        
        // Verify
        assert_eq!(message.message_type, MessageType::RtToBc);
        assert_eq!(message.remote_terminal_address, 3);
        assert_eq!(message.subaddress, 7);
        assert_eq!(message.word_count, 2);
        assert!(message.status_word.is_some());
        assert_eq!(message.status_word.unwrap().value(), status_word);
        assert_eq!(message.data_words.len(), 2);
        assert_eq!(message.data_words[0].value(), data1);
        assert_eq!(message.data_words[1].value(), data2);
    }
} 