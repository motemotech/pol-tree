mod abac_lab;
mod ip_based;

#[path = "pol-tree/cal_shannon_entropy.rs"]
mod cal_shannon_entropy;
#[path = "pol-tree/cal_probabilities.rs"]
mod cal_probabilities;

use abac_lab::parser::Parser;
use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;

use abac_lab::attr_val::*;
use ip_based::entity::{AttributeValue, SourceEntity, DestinationEntity, SourceEntityAttributeKey, DestinationEntityAttributeKey};
use ip_based::rule::*;
use ip_based::classifier::*;
use ip_based::encode_attr::*;

use serde_json::Value;

use cal_probabilities::{
    cal_source_entity_attribute_entropy,
    cal_destination_entity_attribute_entropy,
};

struct LoadedData {
    source_entities: Vec<SourceEntity>,
    destination_entities: Vec<DestinationEntity>,
    policy: Policy
}

fn main() {
    let data = load_entities_and_policy();
    let applicable_rules = list_applicable_rules_per_dest_entity(
        &[data.policy],
        &data.destination_entities,
    );
    println!("Applicable policies per destination entity:");
    for (dest_ip, rules) in applicable_rules {
        println!("Destination IP: {}", dest_ip);
        for rule_id in rules {
            println!("  {}", rule_id);
        }
    }

    let attr_id = AttrIdMap::load("data/ip_based_abac_attr_id.json").expect("attr_id load");
    for src in &data.source_entities {
        let encoded = encode_source_entity(&attr_id, src).expect("encode source");
        println!("Source {}: {:?}", src.ip, encoded);
    }
    for dest in &data.destination_entities {
        let encoded = encode_destination_entity(&attr_id, dest).expect("encode destination");
        println!("Destination {}: {:?}", dest.ip, encoded);
    }
    // apply_policy_rules(&data);
    // calculate_entropies(&data.source_entities, &data.destination_entities);
}

fn load_entities_and_policy() -> LoadedData {
    println!("In File: {}", "data/ip_based_abac_entity.json");
    let json_str = std::fs::read_to_string("data/ip_based_abac_entity.json").expect("File not found");
    let json: Value = serde_json::from_str(&json_str).expect("JSON parse error");

    let mut source_entities: Vec<SourceEntity> = Vec::new();
    if let Some(Value::Array(source_array)) = json.get("source_entities") {
        for entity in source_array {
            match SourceEntity::from_json_value(entity) {
                Ok(entity) => source_entities.push(entity),
                Err(e) => eprintln!("Failed to parse source entity: {}", e),
            }
        }
    }

    let mut destination_entities: Vec<DestinationEntity> = Vec::new();
    if let Some(Value::Array(dest_array)) = json.get("destination_entities") {
        for entity in dest_array {
            match DestinationEntity::from_json_value(entity) {
                Ok(entity) => destination_entities.push(entity),
                Err(e) => eprintln!("Failed to parse destination entity: {}", e),
            }
        }
    }

    println!("Loaded {} source entities", source_entities.len());
    println!("Loaded {} destination entities", destination_entities.len());

    println!("\n=== Loading Policy ===");
    let policy_str = std::fs::read_to_string("data/ip_based_abac_rule.json")
        .expect("Policy file not found");
    let policy_json: Value = serde_json::from_str(&policy_str)
        .expect("Policy JSON parse error");
    
    let policy = Policy::from_json_value(&policy_json)
        .expect("Failed to parse policy");
    
    println!("Policy: {}", policy.policy_name);
    println!("Description: {}", policy.description);
    println!("Default effect: {:?}", policy.default_effect);
    println!("Number of rules: {}", policy.rules.len());

    LoadedData {
        source_entities,
        destination_entities,
        policy
    }
}

// fn apply_policy_rules(data: &LoadedData) {
//     println!("\n=== Applying Policy ===");
    
//     let test_source_count = data.source_entities.len().min(20);
//     let test_dest_count = data.destination_entities.len().min(20);
    
//     for (i, source) in data.source_entities.iter().take(test_source_count).enumerate() {
//         for (j, dest) in data.destination_entities.iter().take(test_dest_count).enumerate() {
//             println!("\n--- Test Case {}: {} -> {} ---", 
//                 i * test_dest_count + j + 1,
//                 source.ip, dest.ip);
            
//             let result = evaluate_policy(&data.policy, source, dest, &data.env);
            
//             match result {
//                 Ok(effect) => {
//                     match effect {
//                         Effect::Allow => println!("  ✓ Access ALLOWED"),
//                         Effect::Deny => println!("  ✗ Access DENIED"),
//                     }
//                 }
//                 Err(e) => {
//                     println!("  ⚠ Error evaluating policy: {}", e);
//                 }
//             }
//         }
//     }
// }

// fn evaluate_policy(
//     policy: &Policy,
//     source: &SourceEntity,
//     destination: &DestinationEntity,
//     env: &HashMap<String, AttributeValue>,
// ) -> Result<Effect, String> {
//     for rule in &policy.rules {
//         match rule.matches(source, destination, env) {
//             Ok(true) => {
//                 println!("    Rule '{}' matched: {}", rule.id, rule.description);
//                 return Ok(rule.effect.clone());
//             }
//             Ok(false) => {
//                 continue;
//             }
//             Err(e) => {
//                 return Err(format!("Error evaluating rule '{}': {}", rule.id, e));
//             }
//         }
//     }
    
//     Ok(policy.default_effect.clone())
// }

// fn calculate_entropies(
//     source_entities: &[SourceEntity],
//     destination_entities: &[DestinationEntity],
// ) {
//     println!("\n=== Calculating Attribute Entropies ===");

//     println!("\n=== Source Entity Attribute Entropies ===");
//     let source_attributes = [
//         SourceEntityAttributeKey::Role,
//         SourceEntityAttributeKey::Dept,
//         SourceEntityAttributeKey::TrustScore,
//         SourceEntityAttributeKey::Groups,
//         SourceEntityAttributeKey::SessionCount,
//     ];

//     for attr_key in &source_attributes {
//         let entropy = cal_source_entity_attribute_entropy(source_entities, attr_key);
//         let attr_name = match attr_key {
//             SourceEntityAttributeKey::Role => "Role",
//             SourceEntityAttributeKey::Dept => "Dept",
//             SourceEntityAttributeKey::TrustScore => "TrustScore",
//             SourceEntityAttributeKey::Groups => "Groups",
//             SourceEntityAttributeKey::SessionCount => "SessionCount",
//         };
//         println!("  {}: {:.4}", attr_name, entropy);
//     }
    
//     // DestinationEntityの各属性のエントロピーを計算
//     println!("\n--- Destination Entity Attribute Entropies ---");
//     let dest_attributes = [
//         DestinationEntityAttributeKey::Type,
//         DestinationEntityAttributeKey::OwnerDept,
//         DestinationEntityAttributeKey::Sensitivity,
//         DestinationEntityAttributeKey::AllowedVLANs,
//     ];
    
//     for attr_key in &dest_attributes {
//         let entropy = cal_destination_entity_attribute_entropy(destination_entities, attr_key);
//         let attr_name = match attr_key {
//             DestinationEntityAttributeKey::Type => "Type",
//             DestinationEntityAttributeKey::OwnerDept => "OwnerDept",
//             DestinationEntityAttributeKey::Sensitivity => "Sensitivity",
//             DestinationEntityAttributeKey::AllowedVLANs => "AllowedVLANs",
//         };
//         println!("  {}: {:.4}", attr_name, entropy);
//     }
// }