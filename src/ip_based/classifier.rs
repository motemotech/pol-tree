use crate::ip_based::entity::{
    SourceEntity, DestinationEntity, AttributeValue,
    SourceEntityAttributeKey, DestinationEntityAttributeKey,
};
use crate::ip_based::rule::{
    Policy, Rule, Effect, Condition, Expression,
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

pub fn list_applicable_policies_per_dest_entity(
    policies: &[Policy],
    dest_entities: &[DestinationEntity],
) -> Vec<(String, Vec<(String, String)>)> {
    dest_entities
        .iter()
        .map(|dest| {
            let applicable: Vec<(String, String)> = policies
                .iter()
                .flat_map(|policy| {
                    policy.rules.iter().filter_map(|rule| {
                        if is_rule_applicable_for_dest_entity(rule, dest) {
                            Some((policy.policy_name.clone(), rule.id.clone()))
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