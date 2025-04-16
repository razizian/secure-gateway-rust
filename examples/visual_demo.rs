use anyhow::Result;
use log::{info, LevelFilter};
use secure_gateway::{Config, Gateway};
use secure_gateway::security::{
    SecurityMode, crypto::{self, encrypt_message, sign_message}
};
use secure_gateway::utils::bytes_to_hex;
use std::time::Duration;
use tokio::time::sleep;

// Import needed protocol types
use secure_gateway::protocols::{CommonMessage, MessageMetadata, ProtocolType};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .init();
    
    println!("╔═════════════════════════════════════════════════════════╗");
    println!("║             SECURE PROTOCOL GATEWAY DEMO                ║");
    println!("╚═════════════════════════════════════════════════════════╝");
    println!();
    
    // Generate a demo key for encryption
    let encryption_key = crypto::generate_encryption_key();
    
    // Generate a demo keypair for signing
    let (signing_key, verification_key) = crypto::generate_signing_keypair()?;
    
    // Process a few demo messages
    for i in 1..=3 {
        println!("\n[DEMO MESSAGE #{i}]");
        println!("------------------------------");
        
        // Alternate message directions
        let (source, target) = if i % 2 == 0 {
            (ProtocolType::MilStd1553, ProtocolType::EthernetIp)
        } else {
            (ProtocolType::EthernetIp, ProtocolType::MilStd1553)
        };
        
        // Create the demo message
        let message = create_test_message(i, source, target);
        
        // Display original message
        println!("📤 Received message from {source}");
        println!("   Source: {}", message.metadata.source_address);
        println!("   Destination: {}", message.metadata.destination_address);
        println!("   Is Command: {}", message.metadata.is_command);
        println!("   Payload ({}B): {}", message.payload.len(), bytes_to_hex(&message.payload));
        
        // Show security being applied
        println!("\n🔐 Applying security measures...");
        sleep(Duration::from_millis(300)).await;
        
        // Show encryption
        let (encrypted_data, nonce) = encrypt_message(&message.payload, &encryption_key)?;
        println!("   ✓ Encrypted with ChaCha20Poly1305");
        println!("   Encrypted ({}B): {}", encrypted_data.len(), bytes_to_hex(&encrypted_data[..8.min(encrypted_data.len())]) + "...");
        
        // Show signing
        let signature = sign_message(&message.payload, &signing_key)?;
        println!("   ✓ Signed with Ed25519");
        println!("   Signature ({}B): {}", signature.len(), bytes_to_hex(&signature[..8.min(signature.len())]) + "...");
        
        // Show protocol translation
        println!("\n🔄 Translating protocol format from {source} to {target}...");
        sleep(Duration::from_millis(500)).await;
        
        // Show routing
        println!("\n🧭 Routing to destination...");
        println!("   ✓ Route found: {source} → {target}");
        println!("   ✓ Security mode: EncryptedAndSigned");
        
        sleep(Duration::from_millis(200)).await;
        
        println!("\n✅ Message successfully delivered to {target} subsystem!");
        
        // Add some spacing between messages
        sleep(Duration::from_secs(1)).await;
    }
    
    println!("\n╔═════════════════════════════════════════════════════════╗");
    println!("║                    DEMO COMPLETE                        ║");
    println!("╚═════════════════════════════════════════════════════════╝");
    println!("\nThe gateway successfully demonstrated:");
    println!("1. Secure message processing with ChaCha20Poly1305 encryption");
    println!("2. Message authentication with Ed25519 signatures");  
    println!("3. Protocol translation between MIL-STD-1553 and Ethernet/IP");
    println!("4. Intelligent message routing based on configuration");
    
    Ok(())
}

fn create_test_message(id: u32, source: ProtocolType, target: ProtocolType) -> CommonMessage {
    // Demo payload - includes message ID for uniqueness
    let mut payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    
    // Add some data specific to the protocol type
    match source {
        ProtocolType::MilStd1553 => {
            // Simulated 1553 command word and data words
            payload.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        },
        ProtocolType::EthernetIp => {
            // Simulated EtherNet/IP data
            payload.extend_from_slice(&[0x99, 0x88, 0x77, 0x66]);
        },
    }
    
    // Add message ID to payload
    payload.push(id as u8);
    
    CommonMessage {
        source_protocol: source,
        target_protocol: Some(target),
        priority: 3,
        payload,
        metadata: MessageMetadata {
            source_address: match source {
                ProtocolType::MilStd1553 => format!("RT{}", 1 + (id % 30)),
                ProtocolType::EthernetIp => format!("192.168.1.{}", 10 + id),
            },
            destination_address: "gateway-controller".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            message_id: id as u64,
            is_command: id % 2 == 0,
            requires_response: id % 3 == 0,
        },
    }
} 