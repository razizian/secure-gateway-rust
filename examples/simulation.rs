use anyhow::Result;
use log::{info, LevelFilter};
use secure_gateway::{Config, Gateway};
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
    
    info!("Starting gateway simulation...");
    
    // Load configuration
    let config = Config::load()?;
    
    // For demo purposes, we'll create a simple message processor
    // that just prints information about the translation
    struct DemoMessageProcessor;
    
    impl DemoMessageProcessor {
        async fn process(&self, message: CommonMessage) -> Result<()> {
            info!(
                "Demo: Processing message from {} to {}: {} bytes payload",
                message.source_protocol,
                message.target_protocol.unwrap_or(message.source_protocol),
                message.payload.len()
            );
            
            // Simulate message translation delay
            sleep(Duration::from_millis(100)).await;
            
            info!(
                "Demo: Translated message {} -> {}: Security applied, message secured",
                message.source_protocol,
                message.target_protocol.unwrap_or(message.source_protocol)
            );
            
            Ok(())
        }
    }
    
    let processor = DemoMessageProcessor;
    
    // Generate test messages
    for i in 1..=10 {
        // Alternate message directions
        let (source, target) = if i % 2 == 0 {
            (ProtocolType::MilStd1553, ProtocolType::EthernetIp)
        } else {
            (ProtocolType::EthernetIp, ProtocolType::MilStd1553)
        };
        
        let message = create_test_message(i, source, target);
        
        info!("Sending test message #{}: {} -> {}", 
              i, message.source_protocol, target);
        
        // Process the message
        processor.process(message).await?;
        
        // Wait a bit between messages
        sleep(Duration::from_secs(1)).await;
    }
    
    info!("Simulation complete! The gateway would normally:");
    info!("1. Parse protocol-specific messages");
    info!("2. Apply security (encryption with ChaCha20Poly1305, signing with Ed25519)");
    info!("3. Translate between protocols");
    info!("4. Route messages to their destinations");
    
    Ok(())
}

/// Create a test message with random data
fn create_test_message(id: u32, source: ProtocolType, target: ProtocolType) -> CommonMessage {
    CommonMessage {
        source_protocol: source,
        target_protocol: Some(target),
        priority: 3,
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF, id as u8],
        metadata: MessageMetadata {
            source_address: format!("device-{}", id),
            destination_address: "gateway".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            message_id: id as u64,
            is_command: true,
            requires_response: true,
        },
    }
} 