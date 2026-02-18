use std::collections::HashMap;
use serde_json::Value;
use crate::ip_based::entity::{
    SourceEntity, DestinationEntity, AttributeValue,
    SourceEntityAttributeKey, DestinationEntityAttributeKey,
};

#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub enum Expression {
    LiteralString(String),
    LiteralNumber(i64),

    AttributeRef(String),

    EnvRef(String),

    Add { operands: Vec<Expression> },
    Multiply { operands: Vec<Expression> },
}

#[derive(Debug, Clone)]
pub enum Condition {
    And { operands: Vec<Condition> },
    Or { operands: Vec<Condition> },

    Eq { lhs: Expression, rhs: Expression },
    Gte { lhs: Expression, rhs: Expression },
    Gt { lhs: Expression, rhs: Expression },
    Lt { lhs: Expression, rhs: Expression },

    In {
        target: Expression,
        check_against: Expression
    },
    InSet {
        value: Expression,
        set: Expression,
    },
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub policy_name: String,
    pub description: String,
    pub default_effect: Effect,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub effect: Effect,
    pub condition: Condition,
}

impl Policy {
    pub fn from_json_value(value: &Value) -> Result<Self, String> {
        let policy_name = value
            .get("policy_name")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'policy_name' field")?
            .to_string();

        let description = value
            .get("description")
            .and_then(|v| v.as_str())
            .ok_or("Missing description field")?
            .to_string();

        let default_effect = value
            .get("default_effect")
            .and_then(|v| v.as_str())
            .ok_or("Missing default_effect field")?;
        let default_effect = match default_effect {
            "allow" => Effect::Allow,
            "deny" => Effect::Deny,
            _ => return Err(format!("Invalid default_effect value: {}", default_effect)),
        };

        let rules_array = value
            .get("rules")
            .and_then(|v| v.as_array())
            .ok_or("Missing rules field")?;

        let rules: Result<Vec<Rule>, String> = rules_array
            .iter()
            .map(|v| Rule::from_json_value(v))
            .collect();

        Ok(Policy {
            policy_name,
            description,
            default_effect,
            rules: rules?,
        })
    }
}

impl Rule {
    pub fn from_json_value(value: &Value) -> Result<Self, String> {
        let id = value
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("Missing id")?
            .to_string();

        let description = value
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        let effect_str = value
            .get("effect")
            .and_then(|v| v.as_str())
            .ok_or("Missing effect")?;
        let effect = match effect_str {
            "allow" => Effect::Allow,
            "deny" => Effect::Deny,
            _ => return Err(format!("Invalid effect value: {}", effect_str)),
        };

        let condition = value
            .get("condition")
            .ok_or("Missing condition")?;
        let condition = Condition::from_json_value(condition)?;

        Ok(Rule {
            id,
            description,
            effect,
            condition,
        })
    }

    pub fn matches(
        &self,
        source: &SourceEntity,
        destination: &DestinationEntity,
        env: &HashMap<String, AttributeValue>,
    ) -> Result<bool, String> {
        self.condition.evaluate(source, destination, env)
    }
}

impl Condition {
    pub fn from_json_value(value: &Value) -> Result<Self, String> {
        let operator = value
            .get("operator")
            .and_then(|v| v.as_str())
            .ok_or("Missing operator")?;

        match operator {
            "AND" | "OR" => {
                let operands_array = value
                    .get("operands")
                    .and_then(|v| v.as_array())
                    .ok_or("Missing operands for logical operator")?;

                let operands: Result<Vec<Condition>, String> = operands_array
                    .iter()
                    .map(|v| Condition::from_json_value(v))
                    .collect();

                match operator {
                    "AND" => Ok(Condition::And { operands: operands? }),
                    "OR" => Ok(Condition::Or { operands: operands? }),
                    _ => unreachable!(),
                }
            }

            "EQ" | "GTE" | "GT" | "LT" => {
                let lhs = value
                    .get("lhs")
                    .ok_or("Missing lhs")?;
                let rhs = value
                    .get("rhs")
                    .ok_or("Missing rhs")?;

                let lhs_expr = Expression::from_json_value(lhs)?;
                let rhs_expr = Expression::from_json_value(rhs)?;

                match operator {
                    "EQ" => Ok(Condition::Eq { lhs: lhs_expr, rhs: rhs_expr }),
                    "GTE" => Ok(Condition::Gte { lhs: lhs_expr, rhs: rhs_expr }),
                    "GT" => Ok(Condition::Gt { lhs: lhs_expr, rhs: rhs_expr }),
                    "LT" => Ok(Condition::Lt { lhs: lhs_expr, rhs: rhs_expr }),
                    _ => unreachable!(),
                }
            }

            "IN" => {
                if let Some(target) = value.get("target") {
                    // 形式1: target と check_against
                    let check_against = value
                        .get("check_against")
                        .ok_or("Missing check_against for IN operator")?;
                    
                    Ok(Condition::In {
                        target: Expression::from_json_value(target)?,
                        check_against: Expression::from_json_value(check_against)?,
                    })
                } else if let Some(value_expr) = value.get("value") {
                    let set = value
                        .get("set")
                        .ok_or("Missing set for IN operator")?;
                    
                    Ok(Condition::InSet {
                        value: Expression::from_json_value(value_expr)?,
                        set: Expression::from_json_value(set)?,
                    })
                } else {
                    Err("IN operator requires either (target, check_against) or (value, set)".to_string())
                }
            }

            _ => Err(format!("Unknown operator: {}", operator)),
        }
    }

    pub fn evaluate(
        &self,
        source: &SourceEntity,
        destination: &DestinationEntity,
        env: &HashMap<String, AttributeValue>,
    ) -> Result<bool, String> {
        match self {
            Condition::And { operands } => {
                for cond in operands {
                    if !cond.evaluate(source, destination, env)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            
            Condition::Or { operands } => {
                for cond in operands {
                    if cond.evaluate(source, destination, env)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            
            Condition::Eq { lhs, rhs } => {
                let lhs_val = lhs.evaluate(source, destination, env)?;
                let rhs_val = rhs.evaluate(source, destination, env)?;
                Ok(lhs_val == rhs_val)
            }
            
            Condition::Gte { lhs, rhs } => {
                let lhs_val = lhs.evaluate(source, destination, env)?;
                let rhs_val = rhs.evaluate(source, destination, env)?;
                Self::compare_values(&lhs_val, &rhs_val, |a, b| a >= b)
            }
            
            Condition::Lt { lhs, rhs } => {
                let lhs_val = lhs.evaluate(source, destination, env)?;
                let rhs_val = rhs.evaluate(source, destination, env)?;
                Self::compare_values(&lhs_val, &rhs_val, |a, b| a < b)
            }
            
            Condition::Gt { lhs, rhs } => {
                let lhs_val = lhs.evaluate(source, destination, env)?;
                let rhs_val = rhs.evaluate(source, destination, env)?;
                Self::compare_values(&lhs_val, &rhs_val, |a, b| a > b)
            }
            
            Condition::In { target, check_against } => {
                let target_val = target.evaluate(source, destination, env)?;
                let set_val = check_against.evaluate(source, destination, env)?;
                
                match (&target_val, &set_val) {
                    (AttributeValue::String(s), AttributeValue::Set(set)) => {
                        Ok(set.contains(s))
                    }
                    _ => Err("IN operator requires String and Set".to_string()),
                }
            }
            
            Condition::InSet { value, set } => {
                let value_val = value.evaluate(source, destination, env)?;
                let set_val = set.evaluate(source, destination, env)?;
                
                match (&value_val, &set_val) {
                    (AttributeValue::String(s), AttributeValue::Set(set)) => {
                        Ok(set.contains(s))
                    }
                    _ => Err("IN operator requires String and Set".to_string()),
                }
            }
        }
    }
    
    /// 数値比較のヘルパー関数
    fn compare_values<F>(lhs: &AttributeValue, rhs: &AttributeValue, cmp: F) -> Result<bool, String>
    where
        F: Fn(i64, i64) -> bool,
    {
        match (lhs, rhs) {
            (AttributeValue::Number(a), AttributeValue::Number(b)) => Ok(cmp(*a, *b)),
            _ => Err("Comparison requires numbers".to_string()),
        }
    }

    pub fn references_dst(&self) -> bool {
        match self {
            Condition::And { operands } | Condition::Or { operands } => {
                operands.iter().any(|c| c.references_dst())
            }
            Condition::Eq { lhs, rhs }
            | Condition::Gte { lhs, rhs }
            | Condition::Gt {lhs, rhs}
            | Condition::Lt {lhs, rhs} => lhs.references_dst() || rhs.references_dst(),
            Condition::In { target, check_against } => {
                target.references_dst() || check_against.references_dst()
            }
            Condition::InSet { value, set } => value.references_dst() || set.references_dst(),
        }
    }

    pub fn evaluate_dest_only(
        &self,
        dest_entity: &DestinationEntity,
    ) -> Result<bool, String> {
        use std::collections::HashMap;
        let empty_env = HashMap::new();
        let dummy_source = SourceEntity {
            ip: String::new(),
            attributes: HashMap::new(),
            desc: None,
        };

        match self {
            Condition::And { operands } => {
                for c in operands {
                    if c.references_dst() && !c.evaluate_dest_only(dest_entity)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Condition::Or { operands } => {
                let mut has_dst = false;
                for c in operands {
                    if c.references_dst() {
                        has_dst = true;
                        if c.evaluate_dest_only(dest_entity)? {
                            return Ok(true);
                        }
                    }
                }
                Ok(!has_dst)
            }
            Condition::Eq { lhs, rhs } => {
                if lhs.references_src_or_env() || rhs.references_src_or_env() {
                    return Ok(true);
                }
                let l = lhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                let r = rhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                Ok(l == r)
            }
            Condition::Gte { lhs, rhs } => {
                if lhs.references_src_or_env() || rhs.references_src_or_env() {
                    return Ok(true);
                }
                let l = lhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                let r = rhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                Self::compare_values(&l, &r, |a, b| a >= b)
            }
            Condition::Gt { lhs, rhs } => {
                if lhs.references_src_or_env() || rhs.references_src_or_env() {
                    return Ok(true);
                }
                let l = lhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                let r = rhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                Self::compare_values(&l, &r, |a, b| a > b)
            }
            Condition::Lt { lhs, rhs } => {
                if lhs.references_src_or_env() || rhs.references_src_or_env() {
                    return Ok(true);
                }
                let l = lhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                let r = rhs.evaluate(&dummy_source, dest_entity, &empty_env)?;
                Self::compare_values(&l, &r, |a, b| a < b)
            }
            Condition::In { target, check_against } => {
                if target.references_src_or_env() || check_against.references_src_or_env() {
                    return Ok(true);
                }
                let t = target.evaluate(&dummy_source, dest_entity, &empty_env)?;
                let c = check_against.evaluate(&dummy_source, dest_entity, &empty_env)?;
                match (&t, &c) {
                    (AttributeValue::String(s), AttributeValue::Set(set)) => Ok(set.contains(s)),
                    _ => Err("IN operator requires String and Set".to_string()),
                }
            }
            Condition::InSet { value, set } => {
                if value.references_src_or_env() || set.references_src_or_env() {
                    return Ok(true);
                }
                let v = value.evaluate(&dummy_source, dest_entity, &empty_env)?;
                let s = set.evaluate(&dummy_source, dest_entity, &empty_env)?;
                match (&v, &s) {
                    (AttributeValue::String(st), AttributeValue::Set(set)) => Ok(set.contains(st)),
                    _ => Err("IN operator requires String and Set".to_string()),
                }
            }
        }
    }
}

impl Expression {
    pub fn from_json_value(value: &Value) -> Result<Self, String> {
        match value {
            Value::String(s) => {
                if s.starts_with("Src.") || s.starts_with("Dst.") {
                    Ok(Expression::AttributeRef(s.clone()))
                } else if s.starts_with("Env.") {
                    Ok(Expression::EnvRef(s.clone()))
                } else {
                    Ok(Expression::LiteralString(s.clone()))
                }
            }
            
            Value::Number(n) => {
                n.as_i64()
                    .ok_or_else(|| format!("Cannot convert to i64: {}", n))
                    .map(Expression::LiteralNumber)
            }
            
            Value::Object(obj) => {
                if let Some(op) = obj.get("operator").and_then(|v| v.as_str()) {
                    match op {
                        "ADD" => {
                            let operands_array = obj
                                .get("operands")
                                .and_then(|v| v.as_array())
                                .ok_or("Missing 'operands' for ADD")?;
                            let operands: Result<Vec<Expression>, String> = operands_array
                                .iter()
                                .map(|v| Expression::from_json_value(v))
                                .collect();
                            Ok(Expression::Add { operands: operands? })
                        }
                        "MULTIPLY" => {
                            let operands_array = obj
                                .get("operands")
                                .and_then(|v| v.as_array())
                                .ok_or("Missing 'operands' for MULTIPLY")?;
                            let operands: Result<Vec<Expression>, String> = operands_array
                                .iter()
                                .map(|v| Expression::from_json_value(v))
                                .collect();
                            Ok(Expression::Multiply { operands: operands? })
                        }
                        _ => Err(format!("Unknown expression operator: {}", op)),
                    }
                } else {
                    Err("Object expression must have 'operator' field".to_string())
                }
            }
            
            _ => Err(format!("Unsupported expression type: {:?}", value)),
        }
    }

    pub fn evaluate(
        &self,
        source: &SourceEntity,
        destination: &DestinationEntity,
        env: &HashMap<String, AttributeValue>,
    ) -> Result<AttributeValue, String> {
        match self {
            Expression::LiteralString(s) => Ok(AttributeValue::String(s.clone())),
            Expression::LiteralNumber(n) => Ok(AttributeValue::Number(*n)),

            Expression::AttributeRef(attr_name) => {
                if attr_name.starts_with("Src.") {
                    Self::get_source_attribute(source, attr_name)
                } else if attr_name.starts_with("Dst.") {
                    Self::get_destination_attribute(destination, attr_name)
                } else {
                    Err(format!("Unknown attribute reference: {}", attr_name))
                }
            }
            
            Expression::EnvRef(env_name) => {
                env.get(env_name)
                    .cloned()
                    .ok_or_else(|| format!("Environment variable not found: {}", env_name))
            }
            
            Expression::Add { operands } => {
                let values: Result<Vec<i64>, String> = operands
                    .iter()
                    .map(|expr| {
                        let val = expr.evaluate(source, destination, env)?;
                        match val {
                            AttributeValue::Number(n) => Ok(n),
                            _ => Err("ADD operands must be numbers".to_string()),
                        }
                    })
                    .collect();
                Ok(AttributeValue::Number(values?.iter().sum()))
            }
            
            Expression::Multiply { operands } => {
                let values: Result<Vec<i64>, String> = operands
                    .iter()
                    .map(|expr| {
                        let val = expr.evaluate(source, destination, env)?;
                        match val {
                            AttributeValue::Number(n) => Ok(n),
                            _ => Err("MULTIPLY operands must be numbers".to_string()),
                        }
                    })
                    .collect();
                Ok(AttributeValue::Number(values?.iter().product()))
            }
        }
    }
    
    fn get_source_attribute(
        source: &SourceEntity,
        attr_name: &str,
    ) -> Result<AttributeValue, String> {
        match attr_name {
            "Src.Role" => source.attributes.get(&SourceEntityAttributeKey::Role)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            "Src.Dept" => source.attributes.get(&SourceEntityAttributeKey::Dept)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            "Src.TrustScore" => source.attributes.get(&SourceEntityAttributeKey::TrustScore)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            "Src.Groups" => source.attributes.get(&SourceEntityAttributeKey::Groups)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            "Src.SessionCount" => source.attributes.get(&SourceEntityAttributeKey::SessionCount)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            _ => Err(format!("Unknown source attribute: {}", attr_name)),
        }
    }
    
    fn get_destination_attribute(
        destination: &DestinationEntity,
        attr_name: &str,
    ) -> Result<AttributeValue, String> {
        match attr_name {
            "Dst.Type" => destination.attributes.get(&DestinationEntityAttributeKey::Type)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            "Dst.OwnerDept" => destination.attributes.get(&DestinationEntityAttributeKey::OwnerDept)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            "Dst.Sensitivity" => destination.attributes.get(&DestinationEntityAttributeKey::Sensitivity)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            "Dst.AllowedVLANs" => destination.attributes.get(&DestinationEntityAttributeKey::AllowedVLANs)
                .cloned()
                .ok_or_else(|| format!("Attribute not found: {}", attr_name)),
            _ => Err(format!("Unknown destination attribute: {}", attr_name)),
        }
    }

    pub fn references_dst(&self) -> bool {
        match self {
            Expression::AttributeRef(name) => name.starts_with("Dst."),
            // 以下の実装は何？
            Expression::Add { operands } | Expression::Multiply { operands } => {
                operands.iter().any(|e| e.references_dst())
            }
            _ => false,
        }
    }

    pub fn references_src_or_env(&self) -> bool {
        match self {
            Expression::AttributeRef(name) => name.starts_with("Src.") || name.starts_with("Env."),
            Expression::Add { operands } | Expression::Multiply { operands } => {
                operands.iter().any(|e| e.references_src_or_env())
            }
            _ => false,
        }
    }
}