//! Message routing functionality
//!
//! This module provides logic to determine how messages should be
//! routed between protocols based on configurable rules.

use anyhow::{anyhow, Result};
use log::debug;
use std::collections::HashMap;

use crate::config::TranslationRule;
use crate::protocols::{CommonMessage, ProtocolType};

/// Message router that determines how messages should be translated and forwarded
pub struct Router {
    /// Rules for message translation
    rules: Vec<TranslationRule>,
    
    /// Quick lookup table by protocol pair
    rule_map: HashMap<(ProtocolType, Option<ProtocolType>), Vec<usize>>,
}

impl Router {
    /// Create a new router with the specified translation rules
    pub fn new(rules: &[TranslationRule]) -> Self {
        // Create a quick lookup map for faster rule matching
        let mut rule_map: HashMap<(ProtocolType, Option<ProtocolType>), Vec<usize>> = HashMap::new();
        
        for (idx, rule) in rules.iter().enumerate() {
            // Create an entry for exact protocol matches
            let key = (rule.source, Some(rule.target));
            
            rule_map.entry(key)
                .or_insert_with(Vec::new)
                .push(idx);
                
            // Also create an entry for wildcard target
            let wildcard_key = (rule.source, None);
            
            rule_map.entry(wildcard_key)
                .or_insert_with(Vec::new)
                .push(idx);
        }
        
        // Sort rule indices by priority (lowest numeric value first)
        for indices in rule_map.values_mut() {
            indices.sort_by_key(|&idx| rules[idx].priority);
        }
        
        Self {
            rules: rules.to_vec(),
            rule_map,
        }
    }
    
    /// Find the appropriate translation rule for a message
    pub fn find_rule<'a>(&'a self, message: &CommonMessage) -> Result<&'a TranslationRule> {
        debug!("Finding route for message: {} -> {:?}", 
            message.source_protocol, message.target_protocol);
            
        // Reject messages where source and target are the same
        if let Some(target) = message.target_protocol {
            if target == message.source_protocol {
                return Err(anyhow!("Cannot translate between the same protocol types: {}", 
                    message.source_protocol));
            }
        }
        
        // First, try to find a rule matching both source and target
        if let Some(target) = message.target_protocol {
            let key = (message.source_protocol, Some(target));
            
            // Check for exact protocol match
            if let Some(indices) = self.rule_map.get(&key) {
                for &idx in indices {
                    let rule = &self.rules[idx];
                    
                    // Check if filter criteria match
                    if self.matches_filter(message, rule) {
                        debug!("Found rule: {}", rule.name);
                        return Ok(rule);
                    }
                }
            }
        }
        
        // If no specific match, try wildcard target
        let wildcard_key = (message.source_protocol, None);
        
        if let Some(indices) = self.rule_map.get(&wildcard_key) {
            for &idx in indices {
                let rule = &self.rules[idx];
                
                // Check if filter criteria match
                if self.matches_filter(message, rule) {
                    debug!("Found wildcard rule: {}", rule.name);
                    return Ok(rule);
                }
            }
        }
        
        // No matching rule found
        Err(anyhow!("No routing rule found for message from {} to {:?}", 
            message.source_protocol, message.target_protocol))
    }
    
    /// Check if a message matches the filter criteria in a rule
    fn matches_filter(&self, message: &CommonMessage, rule: &TranslationRule) -> bool {
        // If there are no filter criteria, the rule matches automatically
        if rule.filter.is_empty() {
            return true;
        }
        
        // Check each filter criterion
        for (key, value) in &rule.filter {
            match key.as_str() {
                "source_address" => {
                    if !value.is_empty() && message.metadata.source_address != *value {
                        return false;
                    }
                },
                "destination_address" => {
                    if !value.is_empty() && message.metadata.destination_address != *value {
                        return false;
                    }
                },
                "priority" => {
                    if let Ok(priority) = value.parse::<u8>() {
                        if message.priority != priority {
                            return false;
                        }
                    }
                },
                "is_command" => {
                    if let Ok(is_command) = value.parse::<bool>() {
                        if message.metadata.is_command != is_command {
                            return false;
                        }
                    }
                },
                "requires_response" => {
                    if let Ok(requires_response) = value.parse::<bool>() {
                        if message.metadata.requires_response != requires_response {
                            return false;
                        }
                    }
                },
                // Additional criteria can be added here
                _ => {
                    // Unknown filter criterion, ignore
                }
            }
        }
        
        // All criteria matched
        true
    }
    
    /// Add a new translation rule
    pub fn add_rule(&mut self, rule: TranslationRule) {
        let idx = self.rules.len();
        
        // Add to the main rules list
        self.rules.push(rule.clone());
        
        // Add to the lookup maps
        let key = (rule.source, Some(rule.target));
        self.rule_map.entry(key)
            .or_insert_with(Vec::new)
            .push(idx);
            
        let wildcard_key = (rule.source, None);
        self.rule_map.entry(wildcard_key)
            .or_insert_with(Vec::new)
            .push(idx);
            
        // Re-sort the affected rule lists
        if let Some(indices) = self.rule_map.get_mut(&key) {
            indices.sort_by_key(|&idx| self.rules[idx].priority);
        }
        
        if let Some(indices) = self.rule_map.get_mut(&wildcard_key) {
            indices.sort_by_key(|&idx| self.rules[idx].priority);
        }
    }
    
    /// Remove a translation rule by name
    pub fn remove_rule(&mut self, name: &str) -> Result<()> {
        // Find the rule index
        let idx = self.rules.iter()
            .position(|r| r.name == name)
            .ok_or_else(|| anyhow!("Rule not found: {}", name))?;
            
        // Remove the rule
        let rule = self.rules.remove(idx);
        
        // Update the lookup maps
        self.rebuild_rule_map();
        
        debug!("Removed rule: {}", name);
        Ok(())
    }
    
    /// Rebuild the rule map after modification
    fn rebuild_rule_map(&mut self) {
        self.rule_map.clear();
        
        for (idx, rule) in self.rules.iter().enumerate() {
            // Add to exact protocol match map
            let key = (rule.source, Some(rule.target));
            self.rule_map.entry(key)
                .or_insert_with(Vec::new)
                .push(idx);
                
            // Add to wildcard target map
            let wildcard_key = (rule.source, None);
            self.rule_map.entry(wildcard_key)
                .or_insert_with(Vec::new)
                .push(idx);
        }
        
        // Sort all rule lists by priority
        for indices in self.rule_map.values_mut() {
            indices.sort_by_key(|&idx| self.rules[idx].priority);
        }
    }
    
    /// Get all routing rules
    pub fn get_rules(&self) -> &[TranslationRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::config::TransformType;
    use crate::protocols::{MessageMetadata, ProtocolType};
    use crate::security::SecurityMode;
    
    fn create_test_rule(name: &str, source: ProtocolType, target: ProtocolType) -> TranslationRule {
        TranslationRule {
            name: name.to_string(),
            source,
            target,
            priority: 5,
            filter: HashMap::new(),
            transform: Some(TransformType::Identity),
            security_mode: SecurityMode::EncryptedAndSigned,
        }
    }
    
    fn create_test_message(source: ProtocolType, target: Option<ProtocolType>) -> CommonMessage {
        CommonMessage {
            source_protocol: source,
            target_protocol: target,
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
    
    #[test]
    fn test_rule_matching() {
        // Create some test rules
        let rules = vec![
            create_test_rule("rule1", ProtocolType::MilStd1553, ProtocolType::EthernetIp),
            create_test_rule("rule2", ProtocolType::EthernetIp, ProtocolType::MilStd1553),
        ];
        
        let router = Router::new(&rules);
        
        // Test finding rules
        let msg1 = create_test_message(ProtocolType::MilStd1553, Some(ProtocolType::EthernetIp));
        let rule1 = router.find_rule(&msg1).unwrap();
        assert_eq!(rule1.name, "rule1");
        
        let msg2 = create_test_message(ProtocolType::EthernetIp, Some(ProtocolType::MilStd1553));
        let rule2 = router.find_rule(&msg2).unwrap();
        assert_eq!(rule2.name, "rule2");
        
        // Test with no matching rule
        // Create a message with the same source and target
        let msg3 = create_test_message(ProtocolType::MilStd1553, Some(ProtocolType::MilStd1553));
        assert!(router.find_rule(&msg3).is_err(), "Should not find a rule for same source and target");
    }
    
    #[test]
    fn test_rule_with_filter() {
        // Create a rule with filter criteria
        let mut rule = create_test_rule("filtered", ProtocolType::MilStd1553, ProtocolType::EthernetIp);
        
        // Add filter: only match messages from "RT1"
        rule.filter.insert("source_address".to_string(), "RT1".to_string());
        
        let rules = vec![rule];
        let router = Router::new(&rules);
        
        // Create message that matches filter
        let mut msg1 = create_test_message(ProtocolType::MilStd1553, Some(ProtocolType::EthernetIp));
        msg1.metadata.source_address = "RT1".to_string();
        
        // Should match
        assert!(router.find_rule(&msg1).is_ok());
        
        // Create message that doesn't match filter
        let mut msg2 = create_test_message(ProtocolType::MilStd1553, Some(ProtocolType::EthernetIp));
        msg2.metadata.source_address = "RT2".to_string();
        
        // Should not match
        assert!(router.find_rule(&msg2).is_err());
    }
    
    #[test]
    fn test_rule_priority() {
        // Create two rules with different priorities for the same protocols
        let mut rule1 = create_test_rule("high-priority", ProtocolType::MilStd1553, ProtocolType::EthernetIp);
        rule1.priority = 1; // Higher priority (lower number)
        
        let mut rule2 = create_test_rule("low-priority", ProtocolType::MilStd1553, ProtocolType::EthernetIp);
        rule2.priority = 10; // Lower priority
        
        // Test with rule2 first in the list
        let router = Router::new(&[rule2.clone(), rule1.clone()]);
        
        let msg = create_test_message(ProtocolType::MilStd1553, Some(ProtocolType::EthernetIp));
        let matched = router.find_rule(&msg).unwrap();
        
        // Should match the high priority rule
        assert_eq!(matched.name, "high-priority");
        assert_eq!(matched.priority, 1);
    }
} 