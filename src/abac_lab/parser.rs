use crate::abac_lab::attr_val::*;
use std::collections::HashMap;

pub struct Parser {
    pub users: Vec<UserAttribute>,
    pub resources: Vec<ResourceAttribute>,
    pub rules: Vec<Rule>,
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            users: Vec::new(),
            resources: Vec::new(),
            rules: Vec::new(),
        }
    }

    pub fn parse_line(&mut self, line: &str) -> Result<(), String> {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }

        if line.starts_with("userAttrib(") {
            let user = self.parse_user_attrib(line)?;
            self.users.push(user);
        } else if line.starts_with("resourceAttrib(") {
            let resource = self.parse_resource_attrib(line)?;
            self.resources.push(resource);
        } else if line.starts_with("rule(") {
            let rule = self.parse_rule(line)?;
            self.rules.push(rule);
        }

        Ok(())
    }

    fn parse_user_attrib(&mut self, line: &str) -> Result<UserAttribute, String> {
        let content = line.strip_prefix("userAttrib(")
            .and_then(|s| s.strip_suffix(")"))
            .ok_or("Invalid userAttrib format")?;

        let parts: Vec<&str> = content.split(',').collect();
        if parts.is_empty() {
            return Err("Missing user ID".to_string());
        }

        let user_id = parts[0].trim().to_string();
        let mut attributes = HashMap::new();

        for part in parts.iter().skip(1) {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                let attr_key = match key {
                    "position" => UserAttributeKey::Position,
                    "department" => UserAttributeKey::Department,
                    "crsTaken" => UserAttributeKey::CrsTaken,
                    "crsTaught" => UserAttributeKey::CrsTaught,
                    "isChair" => UserAttributeKey::IsChair,
                    _ => return Err(format!("Unknown user attribute key: {}", key))
                };

                let attr_value = self.parse_attribute_value(value)?;
                attributes.insert(attr_key, attr_value);
            }
        }

        Ok(UserAttribute {
            user_id,
            attributes,
        })
    }

    fn parse_resource_attrib(&self, line: &str) -> Result<ResourceAttribute, String> {
        let content = line.strip_prefix("resourceAttrib(")
            .and_then(|s| s.strip_suffix(")"))
            .ok_or("Invalid resourceAttrib format")?;

        let parts: Vec<&str> = content.split(',').collect();
        if parts.is_empty() {
            return Err("Missing resource ID".to_string());
        }

        let resource_id = parts[0].trim().to_string();
        let mut attributes = HashMap::new();

        for part in parts.iter().skip(1) {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                let attr_key = match key {
                    "type" => ResourceAttributeKey::Type,
                    "crs" => ResourceAttributeKey::Crs,
                    "student" => ResourceAttributeKey::Student,
                    "departments" => ResourceAttributeKey::Departments,
                    _ => return Err(format!("Unknown resource attribute key: {}", key)),
                };

                let attr_value = self.parse_attribute_value(value)?;
                attributes.insert(attr_key, attr_value);
            }
        }

        Ok(ResourceAttribute {
            resource_id,
            attributes,
        })
    }

    fn parse_rule(&mut self, line: &str) -> Result<Rule, String> {
        let content = line.strip_prefix("rule(")
            .and_then(|s| s.strip_suffix(")"))
            .ok_or("Invalid rule format")?;

        Ok(Rule {
            conditions: Vec::new(),
            actions: Vec::new(),
            resource_type: None,
        })
    }

    fn parse_attribute_value(&self, value: &str) -> Result<AttributeValue, String> {
        if value == "True" {
            return Ok(AttributeValue::Boolean(true));
        }
        if value == "False" {
            return Ok(AttributeValue::Boolean(false));
        }

        if value.starts_with('{') && value.ends_with('}') {
            let content = &value[1..value.len() - 1];
            let items: Vec<String> = content
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            return Ok(AttributeValue::Set(items));
        }

        Ok(AttributeValue::String(value.to_string()))
    }
}