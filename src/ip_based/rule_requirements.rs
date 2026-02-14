use std::collections::HashMap;

use crate::ip_based::entity::{AttributeValue, DestinationEntity, SourceEntity};
use crate::ip_based::rule::{Condition, Expression};

#[derive(Debug, Clone, PartialEq)]
pub enum SrcRequirement {
    Exact { attr: String, value: AttributeValue },
    Containment { attr: String, allowed_set: Vec<String> },
    Numeric {
        attr: String,
        required_ge: Vec<i64>,
        required_lt: Vec<i64>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct MergedRequirements {
    pub role_allowed: Vec<String>,
    pub dept_allowed: Vec<String>,
    pub trust_score_required_ge: Vec<i64>,
    pub trust_score_required_lt: Vec<i64>,
    pub groups_allowed: Vec<String>,
}

fn dummy_source() -> SourceEntity {
    SourceEntity {
        ip: String::new(),
        attributes: HashMap::new(),
        desc: None,
    }
}

fn eval_expr_with_dest(expr: &Expression, dest: &DestinationEntity) -> Result<AttributeValue, String> {
    let empty: HashMap<String, AttributeValue> = HashMap::new();
    expr.evaluate(&dummy_source(), dest, &empty)
}

fn get_src_attr_name(expr: &Expression) -> Option<String> {
    match expr {
        Expression::AttributeRef(name) if name.starts_with("Src.") => Some(name.clone()),
        _ => None,
    }
}

pub fn collect_src_requirements(
    condition: &Condition,
    dest: &DestinationEntity,
) -> Result<Vec<SrcRequirement>, String> {
    let dummy = dummy_source();
    let empty: HashMap<String, AttributeValue> = HashMap::new();

    match condition {
        Condition::And { operands } => {
            let mut out = Vec::new();
            for c in operands {
                out.extend(collect_src_requirements(c, dest)?);
            }
            Ok(out)
        }
        Condition::Or { operands } => {
            let mut out = Vec::new();
            for c in operands {
                out.extend(collect_src_requirements(c, dest)?);
            }
            Ok(out)
        }
        Condition::Eq { lhs, rhs } => {
            let (attr, other) = if let Some(ref attr) = get_src_attr_name(lhs) {
                if rhs.references_src_or_env() {
                    return Ok(vec![]);
                }
                (attr.clone(), rhs)
            } else if let Some(ref attr) = get_src_attr_name(rhs) {
                if lhs.references_src_or_env() {
                    return Ok(vec![]);
                }
                (attr.clone(), lhs)
            } else {
                return Ok(vec![]);
            };
            let value = eval_expr_with_dest(other, dest)?;
            Ok(vec![SrcRequirement::Exact { attr, value }])
        }
        Condition::Gte { lhs, rhs } => {
            if let Some(attr) = get_src_attr_name(lhs) {
                if !rhs.references_src_or_env() {
                    let v = eval_expr_with_dest(rhs, dest)?;
                    if let AttributeValue::Number(t) = v {
                        return Ok(vec![SrcRequirement::Numeric {
                            attr,
                            required_ge: vec![t],
                            required_lt: vec![],
                        }]);
                    }
                }
            }
            if let Some(attr) = get_src_attr_name(rhs) {
                if !lhs.references_src_or_env() {
                    let v = eval_expr_with_dest(lhs, dest)?;
                    if let AttributeValue::Number(t) = v {
                        return Ok(vec![SrcRequirement::Numeric {
                            attr,
                            required_ge: vec![t],
                            required_lt: vec![],
                        }]);
                    }
                }
            }
            Ok(vec![])
        }
        Condition::Gt { lhs, rhs } => {
            if let Some(attr) = get_src_attr_name(lhs) {
                if !rhs.references_src_or_env() {
                    let v = eval_expr_with_dest(rhs, dest)?;
                    if let AttributeValue::Number(t) = v {
                        return Ok(vec![SrcRequirement::Numeric {
                            attr,
                            required_ge: vec![t + 1],
                            required_lt: vec![],
                        }]);
                    }
                }
            }
            if let Some(attr) = get_src_attr_name(rhs) {
                if !lhs.references_src_or_env() {
                    let v = eval_expr_with_dest(lhs, dest)?;
                    if let AttributeValue::Number(t) = v {
                        return Ok(vec![SrcRequirement::Numeric {
                            attr,
                            required_ge: vec![],
                            required_lt: vec![t + 1],
                        }]);
                    }
                }
            }
            Ok(vec![])
        }
        Condition::Lt { lhs, rhs } => {
            if let Some(attr) = get_src_attr_name(lhs) {
                if !rhs.references_src_or_env() {
                    let v = eval_expr_with_dest(rhs, dest)?;
                    if let AttributeValue::Number(t) = v {
                        return Ok(vec![SrcRequirement::Numeric {
                            attr,
                            required_ge: vec![],
                            required_lt: vec![t],
                        }]);
                    }
                }
            }
            if let Some(attr) = get_src_attr_name(rhs) {
                if !lhs.references_src_or_env() {
                    let v = eval_expr_with_dest(lhs, dest)?;
                    if let AttributeValue::Number(t) = v {
                        return Ok(vec![SrcRequirement::Numeric {
                            attr,
                            required_ge: vec![],
                            required_lt: vec![t],
                        }]);
                    }
                }
            }
            Ok(vec![])
        }
        Condition::In { target, check_against } => {
            if let Some(attr) = get_src_attr_name(target) {
                if check_against.references_src_or_env() {
                    return Ok(vec![]);
                }
                let set_val = eval_expr_with_dest(check_against, dest)?;
                if let AttributeValue::Set(allowed) = set_val {
                    return Ok(vec![SrcRequirement::Containment {
                        attr,
                        allowed_set: allowed,
                    }]);
                }
            }
            Ok(vec![])
        }
        Condition::InSet { value, set } => {
            if let Some(attr) = get_src_attr_name(set) {
                if value.references_src_or_env() {
                    return Ok(vec![]);
                }
                let v = eval_expr_with_dest(value, dest)?;
                if let AttributeValue::String(s) = v {
                    return Ok(vec![SrcRequirement::Containment {
                        attr,
                        allowed_set: vec![s],
                    }]);
                }
            }
            Ok(vec![])
        }
    }
}

pub fn merge_requirements(requirements: Vec<SrcRequirement>) -> Result<MergedRequirements, String> {
    let mut out = MergedRequirements::default();

    for req in requirements {
        match req {
            SrcRequirement::Exact { attr, value } => {
                let s = match &value {
                    AttributeValue::String(s) => s.clone(),
                    _ => continue,
                };
                match attr.as_str() {
                    "Src.Role" => {
                        if !out.role_allowed.contains(&s) {
                            out.role_allowed.push(s);
                        }
                    }
                    "Src.Dept" => {
                        if !out.dept_allowed.contains(&s) {
                            out.dept_allowed.push(s);
                        }
                    }
                    _ => {}
                }
            }
            SrcRequirement::Containment { attr, allowed_set } => {
                if attr == "Src.Groups" {
                    for s in allowed_set {
                        if !out.groups_allowed.contains(&s) {
                            out.groups_allowed.push(s);
                        }
                    }
                }
            }
            SrcRequirement::Numeric { attr, required_ge, required_lt } => {
                if attr == "Src.TrustScore" {
                    for t in required_ge {
                        out.trust_score_required_ge.push(t);
                    }
                    for t in required_lt {
                        out.trust_score_required_lt.push(t);
                    }
                }
            }
        }
    }

    if !out.trust_score_required_ge.is_empty() {
        out.trust_score_required_ge.sort();
        out.trust_score_required_ge.dedup();
        let max_ge = *out.trust_score_required_ge.last().unwrap();
        out.trust_score_required_ge = vec![max_ge];
    }
    if !out.trust_score_required_lt.is_empty() {
        out.trust_score_required_lt.sort();
        out.trust_score_required_lt.dedup();
        let min_lt = *out.trust_score_required_lt.first().unwrap();
        out.trust_score_required_lt = vec![min_lt];
    }
    Ok(out)
}