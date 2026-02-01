#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    String(String),
    Set(Vec<String>),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserAttributeKey {
    Position,
    Department,
    CrsTaken,
    CrsTaught,
    IsChair,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceAttributeKey {
    Type,
    Crs,
    Student,
    Departments,
}

#[derive(Debug, Clone)]
pub struct UserAttribute {
    pub user_id: String,
    pub attributes: std::collections::HashMap<UserAttributeKey, AttributeValue>,
}

#[derive(Debug, Clone)]
pub struct ResourceAttribute {
    pub resource_id: String,
    pub attributes: std::collections::HashMap<ResourceAttributeKey, AttributeValue>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<String>,
    pub resource_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RuleCondition {
    AttributeMatch {
        key: String,
        values: Vec<String>,
    },
    AttributeComparison {
        user_key: String,
        resource_key: String,
    },
    UserResourceMatch {
        user_key: String,
        resource_key: String,
    },
}