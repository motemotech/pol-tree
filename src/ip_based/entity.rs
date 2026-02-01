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
}