mod abac_lab;
mod cal_probabilities;
mod cal_shannon_entropy;
mod ip_based;

use abac_lab::parser::Parser;
use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;

use cal_probabilities::*;
use abac_lab::attr_val::*;
use ip_based::entity::{AttributeValue, SourceEntity, DestinationEntity};
use ip_based::rule::*;

use serde_json::Value;

fn main() {
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

    // 2. ポリシーを読み込む
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

    // 3. 環境変数を設定
    let mut env = HashMap::new();
    env.insert("Env.NetworkLoad".to_string(), AttributeValue::Number(85));
    env.insert("Env.DestPort".to_string(), AttributeValue::Number(8080));

    // 4. 各ソース・デスティネーションの組み合わせに対してポリシーを適用
    println!("\n=== Applying Policy ===");
    
    // テスト用に最初の数件だけ評価（全組み合わせは多いので）
    let test_source_count = source_entities.len().min(20);
    let test_dest_count = destination_entities.len().min(20);
    
    for (i, source) in source_entities.iter().take(test_source_count).enumerate() {
        for (j, dest) in destination_entities.iter().take(test_dest_count).enumerate() {
            println!("\n--- Test Case {}: {} -> {} ---", 
                i * test_dest_count + j + 1,
                source.ip, dest.ip);
            
            // ポリシーを評価
            let result = evaluate_policy(&policy, source, dest, &env);
            
            match result {
                Ok(effect) => {
                    match effect {
                        Effect::Allow => println!("  ✓ Access ALLOWED"),
                        Effect::Deny => println!("  ✗ Access DENIED"),
                    }
                }
                Err(e) => {
                    println!("  ⚠ Error evaluating policy: {}", e);
                }
            }
        }
    }
}

/// ポリシーを評価して、最終的な効果（Allow/Deny）を返す
fn evaluate_policy(
    policy: &Policy,
    source: &SourceEntity,
    destination: &DestinationEntity,
    env: &HashMap<String, AttributeValue>,
) -> Result<Effect, String> {
    // ルールを順番に評価
    for rule in &policy.rules {
        match rule.matches(source, destination, env) {
            Ok(true) => {
                // ルールの条件が満たされた場合、そのルールの効果を返す
                println!("    Rule '{}' matched: {}", rule.id, rule.description);
                return Ok(rule.effect.clone());
            }
            Ok(false) => {
                // 条件が満たされなかった場合、次のルールをチェック
                continue;
            }
            Err(e) => {
                // エラーが発生した場合、そのエラーを返す
                return Err(format!("Error evaluating rule '{}': {}", rule.id, e));
            }
        }
    }
    
    // どのルールにもマッチしなかった場合、デフォルトの効果を返す
    Ok(policy.default_effect.clone())
}
