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
use ip_based::encoder::*;

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
        std::slice::from_ref(&data.policy),
        &data.destination_entities,
    );
    
    for (dest_ip, rules) in applicable_rules {
        println!("Destination IP: {}", dest_ip);
        for rule_id in rules {
            println!("  {}", rule_id);
        }
    }

    let attr_id = AttrIdMap::load("data/ip_based_abac_attr_id.json").expect("attr_id load");

    let source_attr_order = [
        "Src.Role",
        "Src.Dept",
        "Src.TrustScore",
        "Src.Groups"
    ];

    // let trust_score_thresholds = [0i64, 50, 80];

    for src in &data.source_entities {
        let encoded = encode_source_entity(&attr_id, src).expect("encode source");
        let bits = encoded_source_to_bit_arrays(&attr_id, &encoded, &source_attr_order).expect("bit arrays");
        println!("Source {}: {:?}", src.ip, bits);
    }

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