use super::auth_types::*;
use async_trait::async_trait;

#[async_trait]
pub trait AuthStorePort {
    async fn set_day0_token(&self, token: &Token) -> Result<(), AuthStoreError>;
    async fn day0_registration(
        &self,
        user: &UserProfile,
        credential: &Credential,
        roles: Vec<Roles>,
        token: &Token,
        lifetime: time::Duration,
    ) -> Result<UserId, AuthStoreError>;
}

#[derive(Debug, Clone)]
pub enum AuthStoreError {
    MisConfiguration(String, String),
    ConnectivityProblem(String, String),
    InternalProblem(String, String),
    InvalidOneTimeToken(String, String),
}

impl std::fmt::Display for AuthStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error = match self {
            AuthStoreError::MisConfiguration(eid, details) => {
                format!("Misconfiguration, eid: {}, details: {}", eid, details)
            }
            AuthStoreError::ConnectivityProblem(eid, details) => {
                format!("Connectivity problem, eid: {}, details: {}", eid, details)
            }
            AuthStoreError::InternalProblem(eid, details) => {
                format!("Internal Problem, eid: {}, details: {}", eid, details)
            }
            AuthStoreError::InvalidOneTimeToken(eid, details) => {
                format!("Internal Problem, eid: {}, details: {}", eid, details)
            }
        };
        f.write_str(&error)
    }
}

impl AuthStoreError {
    pub fn eid(&self) -> &String {
        match self {
            AuthStoreError::MisConfiguration(eid, _) => eid,
            AuthStoreError::ConnectivityProblem(eid, _) => eid,
            AuthStoreError::InternalProblem(eid, _) => eid,
            AuthStoreError::InvalidOneTimeToken(eid, _) => eid,
        }
    }
}
