use anyhow::Result;
use log::{info, LevelFilter};
use secure_gateway::{Config, Gateway};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .init();
    
    info!("Starting secure gateway service...");
    
    // Load configuration
    let config = Config::load()?;
    
    // Create gateway
    let mut gateway = Gateway::new(config);
    
    // Start the gateway in a separate task
    let gateway_handle = tokio::spawn(async move {
        if let Err(e) = gateway.run().await {
            eprintln!("Gateway error: {}", e);
        }
    });
    
    // Wait for Ctrl+C signal
    info!("Gateway started. Press Ctrl+C to shutdown...");
    signal::ctrl_c().await?;
    info!("Shutdown signal received");
    
    // Wait for the gateway task to complete
    if let Err(e) = gateway_handle.await {
        eprintln!("Error joining gateway task: {}", e);
    }
    
    info!("Gateway shutdown complete");
    Ok(())
}
