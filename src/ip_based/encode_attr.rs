use std::collections::HashMap;
use std::fs;
use serde_json::Value;

use crate::ip_based::entity::{
    AttributeValue, SourceEntity, DestinationEntity,
    SourceEntityAttributeKey, DestinationEntityAttributeKey,
};

#[derive(Debug, Clone)]
pub enum AttrValueType {
    Single,
    Multiple,
    Numeric,
}

#[derive(Debug, Clone)]
pub struct AttrIdEntry {
    pub value_type: AttrValueType,
    pub value_to_id: Option<HashMap<String, u32>>,
    pub numeric_min: Option<i64>,
    pub numeric_max: Option<i64>,
}

pub struct AttrIdMap {
    pub entries: HashMap<String, AttrIdEntry>,
}

impl AttrIdMap {
    pub fn load(path: &str) -> Result<Self, String> {
        let s = fs::read_to_string(path).map_err(
            |e| e.to_string()
        )?;
        let json: Value = serde_json::from_str(&s).map_err(
            |e| e.to_string()
        )?;
        let obj = json.as_object().ok_or("attr_id json must be an object")?;

        let mut entries = HashMap::new();
        for (attr_name, attr_val) in obj {
            let entry = Self::parse_attr_entry(attr_val)?;
            entries.insert(attr_name.clone(), entry);
        }
        Ok(AttrIdMap { entries })
    }

    pub fn value_to_id(&self, attr_name: &str, value: &str) -> Result<u32, String> {
        let entry = self.entries.get(attr_name)
            .ok_or_else(|| format!("Unknown attribute: {}", attr_name))?;
        let map = entry.value_to_id.as_ref()
            .ok_or_else(|| format!("Attribute {} has no value->id map", attr_name))?;
        map.get(value).copied()
            .ok_or_else(|| format!("Value '{}' not found in attribute {}", value, attr_name))
    }

    fn parse_attr_entry(v: &Value) -> Result<AttrIdEntry, String> {
        let desc = v.get("description").and_then(|d| d.get("type"))
            .and_then(|t| t.as_str())
            .ok_or("Missing description.type")?;
        let value_obj = v.get("value").and_then(|v| v.as_object())
            .ok_or("Missing value object")?;

        let value_type = match desc {
            "single" => AttrValueType::Single,
            "multiple" => AttrValueType::Multiple,
            "numeric" => AttrValueType::Numeric,
            _ => return Err(format!("Unknown type: {}", desc)),
        };

        let (value_to_id, numeric_min, numeric_max) = if value_obj.contains_key("min") && value_obj.contains_key("max") {
            let min = value_obj.get("min").and_then(|n| n.as_i64()).ok_or("numeric min")?;
            let max = value_obj.get("max").and_then(|n| n.as_i64()).ok_or("numeric max")?;

            (None, Some(min), Some(max))
        } else {
            let mut value_to_id = HashMap::new();
            for (id_str, val) in value_obj {
                let id = id_str.parse::<u32>().map_err(|_| format!("Invalid id: {}", id_str))?;
                let s = val.as_str().ok_or("value must be string for single/multiple")?.to_string();
                value_to_id.insert(s, id);
            }
            (Some(value_to_id), None, None)
        };

        Ok(AttrIdEntry {
            value_type,
            value_to_id,
            numeric_min,
            numeric_max,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EncodedAttributeValue {
    SingleId(u32),
    MultipleIds(Vec<u32>),
    Numeric(i64),
}

pub fn encode_value(
    map: &AttrIdMap,
    attr_name: &str,
    v: &AttributeValue,
) -> Result<EncodedAttributeValue, String> {
    let entry = map.entries.get(attr_name)
        .ok_or_else(|| format!("Unknown attribute: {}", attr_name))?;
    
    match (&entry.value_type, v) {
        (AttrValueType::Single, AttributeValue::String(s)) => {
            let id = map.value_to_id(attr_name, s)?;
            Ok(EncodedAttributeValue::SingleId(id))
        }
        (AttrValueType::Numeric, AttributeValue::Number(n)) => {
            match (entry.numeric_min, entry.numeric_max) {
                (Some(min), Some(max)) => {
                    if *n < min || *n > max {
                        return Err(format!("Numeric value {} out of range [{}, {}]", n, min, max));
                    }
                }
                (Some(min), None) => {
                    if *n < min {
                        return Err(format!("Numeric value {} is below minimum {}", n, min));
                    }
                }
                (None, Some(max)) => {
                    if *n > max {
                        return Err(format!("Numeric value {} above maximu {}", n, max));
                    }
                }
                (None, None) => {}
            }
            Ok(EncodedAttributeValue::Numeric(*n))
        }
        (AttrValueType::Multiple, AttributeValue::Set(vec)) => {
            let ids: Result<Vec<u32>, _> = vec.iter()
                .map(|s| map.value_to_id(attr_name, s))
                .collect();
            Ok(EncodedAttributeValue::MultipleIds(ids?))
        }
        _ => Err(format!(
            "Type mismatch: attribute {} expects {:?}, got {:?}",
            attr_name, entry.value_type, v
        )),
    }
}

pub fn encode_source_entity(
    map: &AttrIdMap,
    entity: &SourceEntity,
) -> Result<HashMap<SourceEntityAttributeKey, EncodedAttributeValue>, String> {
    let mut out = HashMap::new();
    for (key, val) in &entity.attributes {
        let name = SourceEntity::deparse_attribute_key(key)?;
        if map.entries.contains_key(&name) {
            let encoded = encode_value(map, &name, val)?;
            out.insert(key.clone(), encoded);
        }
    }
    Ok(out)
}

pub fn encode_destination_entity(
    map: &AttrIdMap,
    entity: &DestinationEntity,
) -> Result<HashMap<DestinationEntityAttributeKey, EncodedAttributeValue>, String> {
    let mut out = HashMap::new();
    for (key, val) in &entity.attributes {
        let name = DestinationEntity::deparse_attribute_key(key)?;
        if map.entries.contains_key(&name) {
            let encoded = encode_value(map, &name, val)?;
            out.insert(key.clone(), encoded);
        }
    }
    Ok(out)
}

pub fn encoded_value_to_u32(
    entry: &AttrIdEntry,
    v: &EncodedAttributeValue,
) -> Result<u32, String> {
    match (entry, v) {
        (AttrIdEntry { value_type: AttrValueType::Single, .. }, EncodedAttributeValue::SingleId(id)) => {
            Ok(*id)
        }
        (AttrIdEntry { value_type: AttrValueType::Numeric, .. }, EncodedAttributeValue::Numeric(n)) => {
            if *n < 0 || *n > u32::MAX as i64 {
                return Err(format!("Numeric value {} out of u32 range", n));
            }
            Ok(*n as u32)
        }
        (AttrIdEntry { value_type: AttrValueType::Multiple, .. }, EncodedAttributeValue::MultipleIds(ids)) => {
            let mut bits = 0u32;
            for &id in ids {
                if id >= 32 {
                    return Err(format!("Multiple id {} does not fit in 32 bits", id));
                }
                bits |= 1u32 << id;
            }
            Ok(bits)
        }
        _ => Err(format!("Type mismatch in encoded_value_to_u32: entry={:?}, value={:?}", entry.value_type, v)),
    }
}

pub fn u32_to_bit_string(b: u32) -> String {
    (0..32).rev().map(|i| if (b >> i) & 1 == 1 { '1' } else { '0' }).collect()
}

pub fn encoded_source_to_bit_arrays(
    map: &AttrIdMap,
    encoded: &HashMap<SourceEntityAttributeKey, EncodedAttributeValue>,
    attr_order: &[&str],
) -> Result<String, String> {
    let mut out = String::with_capacity(attr_order.len());
    for &name in attr_order {
        let key = SourceEntity::parse_attribute_key(name)?;
        let Some(val) = encoded.get(&key) else { continue };
        let entry = map.entries.get(name).ok_or_else(|| format!("Unknown attr: {}", name))?;
        let u = encoded_value_to_u32(entry, val)?;
        out.push_str(&u32_to_bit_string(u));
    }
    Ok(out)
}
