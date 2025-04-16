//! Protocol implementation modules for the secure gateway
//!
//! This module contains implementations for different aerospace and
//! network protocols supported by the gateway.

pub mod ethernet_ip;
pub mod mil_std_1553;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt::Debug;

/// Common trait for all protocol messages
pub trait Message: Debug + Send + Sync + Any {
    /// Convert message to a standardized format for internal processing
    fn to_common_format(&self) -> Result<CommonMessage>;
    
    /// Get the protocol type of this message
    fn protocol_type(&self) -> ProtocolType;
    
    /// Clone the message as a boxed trait object
    fn clone_box(&self) -> Box<dyn Message>;
    
    /// Convert to Any for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// Enum representing different protocol types supported by the gateway
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolType {
    MilStd1553,
    EthernetIp,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::MilStd1553 => write!(f, "MIL-STD-1553"),
            ProtocolType::EthernetIp => write!(f, "Ethernet/IP"),
        }
    }
}

/// A common message format used for internal processing and translation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonMessage {
    pub source_protocol: ProtocolType,
    pub target_protocol: Option<ProtocolType>,
    pub priority: u8,
    pub payload: Vec<u8>,
    pub metadata: MessageMetadata,
}

/// Metadata associated with a message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub source_address: String,
    pub destination_address: String,
    pub timestamp: u64,
    pub message_id: u64,
    pub is_command: bool,
    pub requires_response: bool,
}

/// A trait for protocol parsers and formatters
pub trait ProtocolHandler: Send + Sync {
    /// Parse raw bytes into a message of this protocol
    fn parse(&self, data: &[u8]) -> Result<Box<dyn Message>>;
    
    /// Format a common message into protocol-specific bytes
    fn format(&self, message: &CommonMessage) -> Result<Vec<u8>>;
    
    /// Get the protocol type handled by this handler
    fn protocol_type(&self) -> ProtocolType;
}

// Factory functions to create protocol handlers
pub fn create_mil_std_1553_handler() -> Box<dyn ProtocolHandler> {
    Box::new(mil_std_1553::Mil1553Handler::new())
}

pub fn create_ethernet_ip_handler() -> Box<dyn ProtocolHandler> {
    Box::new(ethernet_ip::EthernetIpHandler::new())
} 