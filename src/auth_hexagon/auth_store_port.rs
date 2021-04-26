use super::auth_types::*;
use async_trait::async_trait;

#[async_trait]
pub trait AuthStorePort {
    async fn set_day0_token(&self, token: &Token) -> Result<(), AuthStoreError>;
    async fn day0_registration(
        &self,
        user: &UserProfile,
        login_name: &str,
        password_hash: &[u8],
        roles: Vec<Roles>,
        token: &Token,
        lifetime: time::Duration,
    ) -> Result<UserId, AuthStoreError>;
    async fn get_pwd_hash(&self, login_name: &str) -> Result<(UserId, Vec<u8>), AuthStoreError>;
    async fn set_session_id(
        &self,
        user_id: &UserId,
        session_id: &str,
    ) -> Result<(), AuthStoreError>;
    async fn get_user_id_by_session_id(
        &self,
        session_id: &str,
    ) -> Result<Option<UserId>, AuthStoreError>;
    async fn delete_session_id(&self, user_id: &UserId) -> Result<(), AuthStoreError>;
}

#[derive(Debug, Clone)]
pub enum AuthStoreError {
    MisConfiguration(String, String),
    ConnectivityProblem(String, String),
    InternalProblem(String, String),
    InvalidOneTimeToken(String, String),
    DataNotFound(String, String),
    DataNotUnique(String, String),
    InvalidSessionId(String, String),
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
            AuthStoreError::DataNotFound(eid, details) => {
                format!("Data not found, eid: {}, details: {}", eid, details)
            }
            AuthStoreError::DataNotUnique(eid, details) => {
                format!("Data not unique, eid: {}, details: {}", eid, details)
            }
            AuthStoreError::InvalidSessionId(eid, details) => {
                format!("Invalid session id, eid: {}, details: {}", eid, details)
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
            AuthStoreError::DataNotFound(eid, _) => eid,
            AuthStoreError::DataNotUnique(eid, _) => eid,
            AuthStoreError::InvalidSessionId(eid, _) => eid,
        }
    }
}
