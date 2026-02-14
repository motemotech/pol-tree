use crate::ip_based::entity::{
    SourceEntity, DestinationEntity, AttributeValue,
    SourceEntityAttributeKey, DestinationEntityAttributeKey,
};
use crate::ip_based::rule::{
    Policy, Rule, Effect, Condition, Expression,
};
use crate::ip_based::encode_attr::{
    AttrIdMap, 
    merged_requirements_to_key_bits,
    merged_requirements_to_key_bits_per_attr,
    KeySemantics
};
use crate::ip_based::rule_requirements::{
    collect_src_requirements,
    merge_requirements,
    MergedRequirements
};

fn is_rule_applicable_for_dest_entity(
    rule: &Rule,
    dest_entity: &DestinationEntity,
) -> bool {
    if !rule.condition.references_dst() {
        return true;
    }
    rule.condition.evaluate_dest_only(dest_entity) == Ok(true)
}

pub fn list_applicable_rules_per_dest_entity(
    policies: &[Policy],
    dest_entities: &[DestinationEntity],
) -> Vec<(String, Vec<String>)> {
    dest_entities
        .iter()
        .map(|dest| {
            let applicable: Vec<String> = policies
                .iter()
                .flat_map(|policy| {
                    policy.rules.iter().filter_map(|rule| {
                        if is_rule_applicable_for_dest_entity(rule, dest) {
                            Some(rule.id.clone())
                        } else {
                            None
                        }
                    })
                })
                .collect();
            (dest.ip.clone(), applicable)
        })  
        .collect()
}

pub fn build_dest_requirement_bits(
    policies: &[Policy],
    dest_entities: &[DestinationEntity],
    attr_id_map: &AttrIdMap,
    source_attr_order: &[&str],
    trust_score_thresholds: &[i64],
) -> Result<Vec<(String, std::collections::HashMap<String, String>, KeySemantics)>, String> {
    let mut result = Vec::new();
    for dest in dest_entities {
        let mut all_reqs = Vec::new();
        for policy in policies {
            for rule in &policy.rules {
                if !is_rule_applicable_for_dest_entity(rule, dest) {
                    continue;
                }
                let reqs = collect_src_requirements(&rule.condition, dest)?;
                all_reqs.extend(reqs);
            }
        }
        let merged = merge_requirements(all_reqs)?;
        let (key_bits, semantics) = merged_requirements_to_key_bits_per_attr(
            attr_id_map,
            &merged,
            source_attr_order,
            trust_score_thresholds
        )?;
        result.push((dest.ip.clone(), key_bits, semantics));
    }
    Ok(result)
}