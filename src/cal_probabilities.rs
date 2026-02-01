use crate::attr_val::*;
use std::collections::HashMap;

use crate::cal_shannon_entropy::cal_shannon_entropy_from_probabilities;


fn attribute_value_to_key(value: &AttributeValue) -> String {
    match value {
        AttributeValue::String(s) => s.clone(),
        AttributeValue::Boolean(b) => b.to_string(),
        AttributeValue::Set(items) => {
            let mut sorted = items.clone();
            sorted.sort();
            format!("{{{}}}", sorted.join(", "))
        }
    }
}

pub fn cal_user_attribute_probabilities(
    users: &[UserAttribute],
    attribute_key: &UserAttributeKey,
) -> Vec<f64> {
    let mut value_counts: HashMap<String, usize> = HashMap::new();
    let mut total_count = 0;

    for user in users {
        if let Some(value) = user.attributes.get(attribute_key) {
            let key = attribute_value_to_key(value);
            *value_counts.entry(key).or_insert(0) += 1;
            total_count += 1;
        }
    }

    if total_count == 0 {
        return Vec::new();
    }

    let total_f64 = total_count as f64;
    value_counts
        .values()
        .map(|&count| count as f64 / total_f64)
        .collect() 
}

pub fn cal_resource_attribute_probabilities(
    resources: &[ResourceAttribute],
    attribute_key: &ResourceAttributeKey,
) -> Vec<f64> {
    let mut value_counts: HashMap<String, usize> = HashMap::new();
    let mut total_count = 0;

    for resource in resources {
        if let Some(value) = resource.attributes.get(attribute_key) {
            let key = attribute_value_to_key(value);
            *value_counts.entry(key).or_insert(0) += 1;
            total_count += 1;
        }
    }

    if total_count == 0 {
        return Vec::new();
    }

    let total_f64 = total_count as f64;
    value_counts
        .values()
        .map(|&count| count as f64 / total_f64)
        .collect() 
}

pub fn cal_user_attribute_entropy(
    users: &[UserAttribute],
    attribute_key: &UserAttributeKey,
) -> f64 {
    let probabilities = cal_user_attribute_probabilities(users, attribute_key);
    cal_shannon_entropy_from_probabilities(&probabilities)
}

pub fn cal_resource_attribute_entropy(
    resources: &[ResourceAttribute],
    attribute_key: &ResourceAttributeKey,
) -> f64 {
    let probabilities = cal_resource_attribute_probabilities(resources, attribute_key);
    cal_shannon_entropy_from_probabilities(&probabilities)
}