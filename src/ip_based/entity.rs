use std::collections::HashMap;
use serde_json::Value;

fn parse_attribute_value(val: &Value) -> Result<AttributeValue, String> {
    match val {
        Value::String(s) => Ok(AttributeValue::String(s.clone())),

        Value::Number(n) => {
            n.as_i64()
                .ok_or_else(|| format!("Cannot convert number to i64: {}", n))
                .map(AttributeValue::Number)
        }

        Value::Array(arr) => {
            arr.iter()
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| format!("Array element is not a string: {:?}", v))
                        .map(|s| s.to_string())
                })
                .collect::<Result<Vec<String>, String>>()
                .map(AttributeValue::Set)
        }

        Value::Bool(b) => Ok(AttributeValue::Boolean(*b)),

        _ => Err(format!("Unsupported attribute value type: {:?}", val)),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    String(String),
    Number(i64),
    Set(Vec<String>),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceEntityAttributeKey {
    Role,
    Dept,
    TrustScore,
    Groups,
    SessionCount,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DestinationEntityAttributeKey {
    Type,
    OwnerDept,
    Sensitivity,
    AllowedVLANs,
}

#[derive(Debug, Clone)]
pub struct SourceEntity {
    pub ip: String,
    pub attributes: HashMap<SourceEntityAttributeKey, AttributeValue>,
    pub desc: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DestinationEntity {
    pub ip: String,
    pub attributes: HashMap<DestinationEntityAttributeKey, AttributeValue>,
    pub desc: Option<String>,
}

impl SourceEntity {
    pub fn from_json_value(value: &Value) -> Result<Self, String> {
        let ip = value
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ip' field")?
            .to_string();

        let desc = value
            .get("desc")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let attributes_obj = value
            .get("attributes")
            .and_then(|v| v.as_object())
            .ok_or("Missing or invalid 'attributes' field")?;

        let mut attributes = HashMap::new();
        for (key, val) in attributes_obj {
            let attr_key = Self::parse_attribute_key(key)?;
            let attr_value = Self::parse_attribute_value(val)?;
            attributes.insert(attr_key, attr_value);
        }

        Ok(Self {
            ip,
            attributes,
            desc,
        })
    }

    fn parse_attribute_key(key: &str) -> Result<SourceEntityAttributeKey, String> {
        match key {
            "Src.Role" => Ok(SourceEntityAttributeKey::Role),
            "Src.Dept" => Ok(SourceEntityAttributeKey::Dept),
            "Src.TrustScore" => Ok(SourceEntityAttributeKey::TrustScore),
            "Src.Groups" => Ok(SourceEntityAttributeKey::Groups),
            "Src.SessionCount" => Ok(SourceEntityAttributeKey::SessionCount),
            _ => Err(format!("Unknown source entity attribute key: {}", key)),
        }
    }

    fn parse_attribute_value(val: &Value) -> Result<AttributeValue, String> {
        parse_attribute_value(val)
    }
}

impl DestinationEntity {
    pub fn from_json_value(value: &Value) -> Result<Self, String> {    
        let ip = value
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'ip' field")?
            .to_string();

        let desc = value
            .get("desc")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let attributes_obj = value
            .get("attributes")
            .and_then(|v| v.as_object())
            .ok_or("Missing or invalid 'attributes' field")?;

        let mut attributes = HashMap::new();

        for (key, val) in attributes_obj {
            let attr_key = Self::parse_attribute_key(key)?;
            let attr_value = Self::parse_attribute_value(val)?;
            attributes.insert(attr_key, attr_value);
        }

        Ok(DestinationEntity {
            ip,
            attributes,
            desc,
        })
    }

    fn parse_attribute_key(key: &str) -> Result<DestinationEntityAttributeKey, String> {
        match key {
            "Dst.Type" => Ok(DestinationEntityAttributeKey::Type),
            "Dst.OwnerDept" => Ok(DestinationEntityAttributeKey::OwnerDept),
            "Dst.Sensitivity" => Ok(DestinationEntityAttributeKey::Sensitivity),
            "Dst.AllowedVLANs" => Ok(DestinationEntityAttributeKey::AllowedVLANs),
            _ => Err(format!("Unknown destination attribute key: {}", key)),
        }
    }

    fn parse_attribute_value(val: &Value) -> Result<AttributeValue, String> {
        parse_attribute_value(val)
    }
}