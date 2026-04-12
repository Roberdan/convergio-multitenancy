//! Core types for multi-tenancy isolation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum length for an org identifier.
const MAX_ORG_ID_LEN: usize = 128;

/// Strongly-typed org identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgId(pub String);

impl OrgId {
    /// Create a validated OrgId. Rejects empty, oversized, or invalid identifiers.
    pub fn new(id: impl Into<String>) -> Result<Self, TenancyError> {
        let id = id.into();
        if id.is_empty() {
            return Err(TenancyError::InvalidOrgId(
                "org_id must not be empty".into(),
            ));
        }
        if id.len() > MAX_ORG_ID_LEN {
            return Err(TenancyError::InvalidOrgId(format!(
                "org_id exceeds {MAX_ORG_ID_LEN} chars"
            )));
        }
        // Must start with alphanumeric, contain only alphanumeric/hyphen/underscore
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(TenancyError::InvalidOrgId(
                "org_id must be alphanumeric, hyphens, or underscores only".into(),
            ));
        }
        if !id.chars().next().unwrap_or('_').is_ascii_alphanumeric() {
            return Err(TenancyError::InvalidOrgId(
                "org_id must start with alphanumeric character".into(),
            ));
        }
        Ok(Self(id))
    }

    /// Sanitized prefix for DB table names (alphanumeric + underscore only).
    /// Hyphens are replaced with underscores; the raw org_id is preserved
    /// separately to avoid collisions (e.g. "org-a" vs "org_a").
    pub fn table_prefix(&self) -> String {
        let sanitized: String = self
            .0
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        // Include a hash suffix to prevent prefix collisions between
        // org ids that differ only in non-alphanumeric chars (e.g. "org-a" vs "org_a").
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.0.as_bytes());
        let hash = format!("{:x}", h.finalize());
        let short_hash = &hash[..8];
        format!("org_{sanitized}_{short_hash}_")
    }
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for OrgId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Isolation policy for an org.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationPolicy {
    pub org_id: OrgId,
    pub db_prefix_enabled: bool,
    pub network_whitelist_enabled: bool,
    pub secret_scope_enabled: bool,
    pub audit_isolation_enabled: bool,
    pub resource_limits_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IsolationPolicy {
    pub fn new_default(org_id: OrgId) -> Self {
        let now = Utc::now();
        Self {
            org_id,
            db_prefix_enabled: true,
            network_whitelist_enabled: true,
            secret_scope_enabled: true,
            audit_isolation_enabled: true,
            resource_limits_enabled: true,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Per-org resource limits (soft tracking, no OS enforcement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub org_id: OrgId,
    pub max_cpu_seconds_per_hour: u64,
    pub max_memory_mb: u64,
    pub max_storage_mb: u64,
    pub max_concurrent_agents: u32,
    pub max_api_calls_per_minute: u32,
}

impl ResourceLimits {
    pub fn default_for(org_id: OrgId) -> Self {
        Self {
            org_id,
            max_cpu_seconds_per_hour: 3600,
            max_memory_mb: 4096,
            max_storage_mb: 10240,
            max_concurrent_agents: 20,
            max_api_calls_per_minute: 600,
        }
    }
}

/// Current resource usage snapshot for an org.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub org_id: OrgId,
    pub cpu_seconds_this_hour: f64,
    pub memory_mb_current: f64,
    pub storage_mb_current: f64,
    pub active_agents: u32,
    pub api_calls_this_minute: u32,
    pub recorded_at: DateTime<Utc>,
}

/// A peer node whitelisted for an org's mesh sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerWhitelist {
    pub org_id: OrgId,
    pub peer_name: String,
    pub peer_url: String,
    pub allowed: bool,
    pub created_at: DateTime<Utc>,
}

/// Scoped secret entry — invisible across org boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedSecret {
    pub org_id: OrgId,
    pub key: String,
    /// Value is stored encrypted; this holds the ciphertext.
    pub encrypted_value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Org-scoped audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAuditEntry {
    pub id: Option<i64>,
    pub org_id: OrgId,
    pub agent_id: String,
    pub action: String,
    pub target: String,
    pub details: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Violation type when isolation is breached.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ViolationType {
    CrossOrgDbAccess,
    UnauthorizedPeer,
    CrossOrgSecretAccess,
    CrossOrgAuditAccess,
    ResourceLimitExceeded,
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrossOrgDbAccess => write!(f, "cross_org_db_access"),
            Self::UnauthorizedPeer => write!(f, "unauthorized_peer"),
            Self::CrossOrgSecretAccess => write!(f, "cross_org_secret_access"),
            Self::CrossOrgAuditAccess => write!(f, "cross_org_audit_access"),
            Self::ResourceLimitExceeded => write!(f, "resource_limit_exceeded"),
        }
    }
}

/// A recorded isolation violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationViolation {
    pub id: Option<i64>,
    pub org_id: OrgId,
    pub violation_type: ViolationType,
    pub details: String,
    pub blocked: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TenancyError {
    #[error("isolation violation: {0}")]
    IsolationViolation(String),
    #[error("invalid org_id: {0}")]
    InvalidOrgId(String),
    #[error("org not found: {0}")]
    OrgNotFound(String),
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    #[error("db error: {0}")]
    Db(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_id_table_prefix_sanitization() {
        let org = OrgId("acme-corp".into());
        let prefix = org.table_prefix();
        assert!(prefix.starts_with("org_acme_corp_"));
        assert!(prefix.ends_with('_'));
    }

    #[test]
    fn org_id_display() {
        let org = OrgId("my-org".into());
        assert_eq!(format!("{org}"), "my-org");
    }

    #[test]
    fn default_resource_limits() {
        let limits = ResourceLimits::default_for(OrgId("test".into()));
        assert_eq!(limits.max_concurrent_agents, 20);
    }

    #[test]
    fn org_id_new_rejects_empty() {
        assert!(OrgId::new("").is_err());
    }

    #[test]
    fn org_id_new_rejects_special_chars() {
        assert!(OrgId::new("'; DROP TABLE users; --").is_err());
        assert!(OrgId::new("evil/../../etc").is_err());
        assert!(OrgId::new("org with spaces").is_err());
    }

    #[test]
    fn org_id_new_rejects_leading_non_alpha() {
        assert!(OrgId::new("-leading-hyphen").is_err());
        assert!(OrgId::new("_leading-underscore").is_err());
    }

    #[test]
    fn org_id_new_accepts_valid() {
        assert!(OrgId::new("acme").is_ok());
        assert!(OrgId::new("acme-corp").is_ok());
        assert!(OrgId::new("org_123").is_ok());
    }

    #[test]
    fn prefix_collision_prevented() {
        let org1 = OrgId("org-a".into());
        let org2 = OrgId("org_a".into());
        assert_ne!(org1.table_prefix(), org2.table_prefix());
    }

    #[test]
    fn org_id_too_long() {
        let long_id: String = "a".repeat(MAX_ORG_ID_LEN + 1);
        assert!(OrgId::new(long_id).is_err());
    }
}
