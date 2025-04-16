//! Gateway implementation for secure protocol translation
//!
//! This module contains the core gateway functionality for receiving,
//! processing, and routing messages between different protocols.

pub mod router;
pub mod transformer;

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use std::time::Duration;

use crate::config::Config;
use crate::protocols::{
    CommonMessage, ProtocolHandler, ProtocolType,
    create_ethernet_ip_handler, create_mil_std_1553_handler
};
use crate::security::{SecurityService, key_manager::KeyManager};

use router::Router;
use transformer::Transformer;

/// Command types for the gateway control channel
enum GatewayCommand {
    /// Process an incoming message
    ProcessMessage {
        message: CommonMessage,
        result_tx: oneshot::Sender<Result<()>>,
    },
    
    /// Shutdown the gateway
    Shutdown {
        result_tx: oneshot::Sender<Result<()>>,
    },
}

/// Secure communication gateway
pub struct Gateway {
    /// Gateway configuration
    config: Config,
    
    /// Protocol handlers
    handlers: HashMap<ProtocolType, Box<dyn ProtocolHandler>>,
    
    /// Security service
    security: Arc<SecurityService>,
    
    /// Message router
    router: Arc<Router>,
    
    /// Message transformer
    transformer: Arc<Transformer>,
    
    /// Command channel
    command_tx: Option<mpsc::Sender<GatewayCommand>>,
    
    /// Shutdown flag
    is_shutting_down: Arc<Mutex<bool>>,
}

impl Gateway {
    /// Create a new gateway with the specified configuration
    pub fn new(config: Config) -> Self {
        // Create the protocol handlers
        let mut handlers = HashMap::new();
        handlers.insert(ProtocolType::MilStd1553, create_mil_std_1553_handler());
        handlers.insert(ProtocolType::EthernetIp, create_ethernet_ip_handler());
        
        // Create key manager
        let key_manager = if let Some(path) = &config.security.key_storage_path {
            match KeyManager::new_persistent(path) {
                Ok(km) => km,
                Err(e) => {
                    warn!("Failed to create persistent key manager: {}", e);
                    warn!("Falling back to in-memory key manager");
                    KeyManager::new()
                }
            }
        } else {
            KeyManager::new()
        };
        
        // Create security service
        let security = Arc::new(SecurityService::new(key_manager));
        
        // Create router and transformer
        let router = Arc::new(Router::new(&config.translation_rules));
        let transformer = Arc::new(Transformer::new());
        
        Self {
            config,
            handlers,
            security,
            router,
            transformer,
            command_tx: None,
            is_shutting_down: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start the gateway
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting gateway with {} worker threads", self.config.get_worker_count());
        
        // Create command channel
        let (command_tx, mut command_rx) = mpsc::channel(self.config.general.queue_size);
        self.command_tx = Some(command_tx.clone());
        
        // Set up key rotation if enabled
        if let Some(days) = self.config.security.key_rotation_days {
            self.setup_key_rotation(days)?;
        }
        
        // Start protocol interfaces
        self.start_interfaces()?;
        
        // Enter the main processing loop
        let security = Arc::clone(&self.security);
        let router = Arc::clone(&self.router);
        let transformer = Arc::clone(&self.transformer);
        let is_shutting_down = Arc::clone(&self.is_shutting_down);
        
        info!("Gateway main loop started");
        
        // Process messages until shutdown is requested
        while let Some(cmd) = command_rx.recv().await {
            match cmd {
                GatewayCommand::ProcessMessage { message, result_tx } => {
                    let result = process_message(
                        message, 
                        &security, 
                        &router, 
                        &transformer,
                        &command_tx
                    ).await;
                    
                    // Send result back to caller
                    if let Err(e) = result_tx.send(result) {
                        error!("Failed to send result: {:?}", e);
                    }
                },
                
                GatewayCommand::Shutdown { result_tx } => {
                    info!("Processing shutdown command");
                    
                    // Set shutdown flag
                    *is_shutting_down.lock().unwrap() = true;
                    
                    // Perform shutdown tasks
                    // (In a real system, this would cleanly shut down protocol handlers)
                    
                    // Notify caller that shutdown is complete
                    let _ = result_tx.send(Ok(()));
                    
                    // Exit the loop
                    break;
                }
            }
        }
        
        info!("Gateway main loop exited");
        Ok(())
    }
    
    /// Set up automatic key rotation
    fn setup_key_rotation(&self, days: u64) -> Result<()> {
        info!("Setting up automatic key rotation every {} days", days);
        
        // Create clone of key IDs
        let enc_key = self.config.security.default_encryption_key.clone();
        let sign_key = self.config.security.default_signing_key.clone();
        
        // Get key manager reference
        // In a real system, we would need to ensure thread-safety here
        // by extracting key_manager from the security service Arc
        
        // Set up task (in a real implementation)
        // This would be implemented as a background task that rotates keys
        // at the specified interval
        
        Ok(())
    }
    
    /// Start protocol interfaces
    fn start_interfaces(&self) -> Result<()> {
        // In a real implementation, this would start listeners for each protocol
        // and set up channels to feed messages to the main gateway
        
        info!("Protocol interfaces started");
        Ok(())
    }
    
    /// Submit a message for processing
    pub async fn process_message(&self, message: CommonMessage) -> Result<()> {
        if let Some(tx) = &self.command_tx {
            // Create oneshot channel for result
            let (result_tx, result_rx) = oneshot::channel();
            
            // Send to processing loop
            tx.send(GatewayCommand::ProcessMessage {
                message,
                result_tx,
            }).await.map_err(|_| anyhow!("Gateway processing channel closed"))?;
            
            // Wait for result
            result_rx.await.map_err(|_| anyhow!("Failed to receive processing result"))?
        } else {
            Err(anyhow!("Gateway not running"))
        }
    }
    
    /// Shutdown the gateway
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down gateway");
        
        if let Some(tx) = &self.command_tx {
            // Create oneshot channel for result
            let (result_tx, result_rx) = oneshot::channel();
            
            // Send shutdown command
            tx.send(GatewayCommand::Shutdown {
                result_tx,
            }).await.map_err(|_| anyhow!("Gateway command channel closed"))?;
            
            // Wait for confirmation
            let _ = result_rx.await.map_err(|_| anyhow!("Failed to receive shutdown confirmation"))?;
            
            // Wait a bit to ensure all tasks have a chance to complete
            sleep(Duration::from_millis(500)).await;
            
            info!("Gateway shutdown complete");
            Ok(())
        } else {
            warn!("Gateway was not running");
            Ok(())
        }
    }
}

/// Process a single message through the gateway pipeline
async fn process_message(
    message: CommonMessage,
    security: &SecurityService,
    router: &Router,
    transformer: &Transformer,
    command_tx: &mpsc::Sender<GatewayCommand>,
) -> Result<()> {
    info!("Processing message: {} -> {:?}", message.source_protocol, message.target_protocol);
    
    // Find routing rule
    let rule = router.find_rule(&message)?;
    
    // Apply transformation
    let transformed = transformer.transform(&message, rule)?;
    
    // Apply security
    let secured = security.secure_message(
        &bincode::serialize(&transformed)?,
        rule.security_mode,
        &"default-encryption", // In a real system, this would be based on destination
    )?;
    
    // Serialize the secured message
    let secured_bytes = security.serialize(&secured)?;
    
    // In a real implementation, this would send the secured message
    // to the appropriate outbound protocol handler
    info!("Message translated from {} to {}: {} bytes secure payload", 
          message.source_protocol, rule.target, secured_bytes.len());
    
    Ok(())
} 