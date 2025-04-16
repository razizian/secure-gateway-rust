//! Message transformation functionality
//!
//! This module provides the ability to transform messages between
//! different protocols according to configurable rules.

use anyhow::{anyhow, Result};
use log::debug;
use std::collections::HashMap;

use crate::config::{TransformType, TranslationRule};
use crate::protocols::CommonMessage;

/// Message transformer that applies transformations to messages during protocol translation
pub struct Transformer {
    // Custom transformation modules could be registered here
    transform_modules: HashMap<String, Box<dyn TransformModule>>,
}

/// Trait for custom transform modules
pub trait TransformModule: Send + Sync {
    fn transform(&self, message: &CommonMessage) -> Result<CommonMessage>;
    fn name(&self) -> &str;
}

impl Transformer {
    /// Create a new transformer
    pub fn new() -> Self {
        let transform_modules = HashMap::new();
        
        Self {
            transform_modules,
        }
    }
    
    /// Register a custom transformation module
    pub fn register_module(&mut self, module: Box<dyn TransformModule>) {
        let name = module.name().to_string();
        self.transform_modules.insert(name, module);
    }
    
    /// Apply a transformation to a message based on a rule
    pub fn transform(&self, message: &CommonMessage, rule: &TranslationRule) -> Result<CommonMessage> {
        // Start with a clone of the original message
        let mut transformed = message.clone();
        
        // Update target protocol to the rule's target
        transformed.target_protocol = Some(rule.target);
        
        // Apply transformation if specified
        if let Some(transform) = &rule.transform {
            match transform {
                TransformType::FieldMap(map) => {
                    self.apply_field_map(&mut transformed, map)?;
                },
                
                TransformType::Custom(module_name) => {
                    transformed = self.apply_custom_transform(&transformed, module_name)?;
                },
                
                TransformType::Identity => {
                    // Identity transformation - do nothing
                    debug!("Applying identity transformation");
                },
            }
        }
        
        debug!("Message transformed from {} to {}", 
            message.source_protocol, rule.target);
            
        Ok(transformed)
    }
    
    /// Apply a field mapping transformation
    fn apply_field_map(&self, message: &mut CommonMessage, map: &HashMap<String, String>) -> Result<()> {
        debug!("Applying field map transformation");
        
        // A real implementation would look at each field mapping and transform the message
        // This is a simplified version that just notes we're doing something
        
        // Example: If we had a field named "priority" that needed mapping
        if let Some(priority_str) = map.get("priority") {
            if let Ok(priority) = priority_str.parse::<u8>() {
                message.priority = priority;
            }
        }
        
        Ok(())
    }
    
    /// Apply a custom transformation
    fn apply_custom_transform(&self, message: &CommonMessage, module_name: &str) -> Result<CommonMessage> {
        debug!("Applying custom transformation: {}", module_name);
        
        // Look up the transform module
        let module = self.transform_modules.get(module_name)
            .ok_or_else(|| anyhow!("Transform module not found: {}", module_name))?;
            
        // Apply the transformation
        module.transform(message)
    }
}

/// Example custom transformation module
pub struct HeaderEnrichmentTransform {
    name: String,
    enrichment_fields: HashMap<String, String>,
}

impl HeaderEnrichmentTransform {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            enrichment_fields: HashMap::new(),
        }
    }
    
    pub fn add_field(&mut self, key: &str, value: &str) {
        self.enrichment_fields.insert(key.to_string(), value.to_string());
    }
}

impl TransformModule for HeaderEnrichmentTransform {
    fn transform(&self, message: &CommonMessage) -> Result<CommonMessage> {
        // Create a copy of the message
        let mut transformed = message.clone();
        
        // For a real implementation, we would add fields to the message's
        // metadata based on the enrichment fields
        
        // Just a placeholder for demonstration purposes
        transformed.priority = message.priority.saturating_add(1);
        
        Ok(transformed)
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TransformType, TranslationRule};
    use crate::protocols::{CommonMessage, MessageMetadata, ProtocolType};
    use crate::security::SecurityMode;
    
    // Helper function to create a test message
    fn create_test_message() -> CommonMessage {
        CommonMessage {
            source_protocol: ProtocolType::MilStd1553,
            target_protocol: Some(ProtocolType::EthernetIp),
            priority: 3,
            payload: vec![1, 2, 3, 4],
            metadata: MessageMetadata {
                source_address: "test-source".to_string(),
                destination_address: "test-dest".to_string(),
                timestamp: 12345,
                message_id: 67890,
                is_command: true,
                requires_response: true,
            },
        }
    }
    
    // Helper function to create a test rule
    fn create_test_rule(transform: Option<TransformType>) -> TranslationRule {
        TranslationRule {
            name: "test-rule".to_string(),
            source: ProtocolType::MilStd1553,
            target: ProtocolType::EthernetIp,
            priority: 5,
            filter: HashMap::new(),
            transform,
            security_mode: SecurityMode::EncryptedAndSigned,
        }
    }
    
    #[test]
    fn test_identity_transform() {
        let transformer = Transformer::new();
        let message = create_test_message();
        let rule = create_test_rule(Some(TransformType::Identity));
        
        let result = transformer.transform(&message, &rule).unwrap();
        
        // Identity transform should keep the same payload and metadata
        assert_eq!(result.payload, message.payload);
        assert_eq!(result.metadata.source_address, message.metadata.source_address);
        assert_eq!(result.metadata.destination_address, message.metadata.destination_address);
        
        // But target protocol should be updated to the rule's target
        assert_eq!(result.target_protocol, Some(ProtocolType::EthernetIp));
    }
    
    #[test]
    fn test_field_map_transform() {
        let transformer = Transformer::new();
        let message = create_test_message();
        
        // Create a field map that sets priority to 10
        let mut field_map = HashMap::new();
        field_map.insert("priority".to_string(), "10".to_string());
        
        let rule = create_test_rule(Some(TransformType::FieldMap(field_map)));
        
        let result = transformer.transform(&message, &rule).unwrap();
        
        // Priority should be updated
        assert_eq!(result.priority, 10);
        
        // Other fields should remain the same
        assert_eq!(result.payload, message.payload);
    }
    
    #[test]
    fn test_custom_transform() {
        let mut transformer = Transformer::new();
        
        // Register a custom transformation module
        let mut enrichment = HeaderEnrichmentTransform::new("test-enrichment");
        enrichment.add_field("source", "enriched-source");
        
        transformer.register_module(Box::new(enrichment));
        
        let message = create_test_message();
        let rule = create_test_rule(Some(TransformType::Custom("test-enrichment".to_string())));
        
        let result = transformer.transform(&message, &rule).unwrap();
        
        // Priority should be incremented by the custom transform
        assert_eq!(result.priority, message.priority + 1);
    }
    
    #[test]
    fn test_missing_custom_transform() {
        let transformer = Transformer::new();
        let message = create_test_message();
        
        // Reference a non-existent transform module
        let rule = create_test_rule(Some(TransformType::Custom("non-existent".to_string())));
        
        // Should fail because the module doesn't exist
        assert!(transformer.transform(&message, &rule).is_err());
    }
} 