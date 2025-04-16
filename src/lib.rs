//! Secure Gateway for Aerospace Communication Protocols
//!
//! This library provides secure translation between legacy aerospace protocols
//! (like MIL-STD-1553) and modern IP-based networks.

pub mod config;
pub mod gateway;
pub mod protocols;
pub mod security;
pub mod utils;

pub use config::Config;
pub use gateway::Gateway; 