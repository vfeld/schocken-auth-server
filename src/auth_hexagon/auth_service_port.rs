use super::auth_types::*;
use async_trait::async_trait;

#[async_trait]
pub trait AuthServicePort {
    /// Store a new day0 token, in case the token is alreadz stored this function does nothing and returns successfull
    async fn set_day0_token(&self, token: &Token) -> Result<(), AuthServiceError>;
    /// Registers user profile and credential in case the day0 token was not used before and is not expired
    async fn day0_registration(
        &self,
        user: &UserProfile,
        credential: &Credential,
        token: &Token,
    ) -> Result<UserId, AuthServiceError>;
    /// Authenticate using user name and password
    async fn auth_credential(&self, credential: &Credential) -> Result<UserId, AuthServiceError>;
    async fn create_session_token(
        &self,
        user_id: &UserId,
    ) -> Result<(SessionToken, time::OffsetDateTime), AuthServiceError>;
    async fn auth_session_token(
        &self,
        session_token: &SessionToken,
    ) -> Result<(UserId, time::OffsetDateTime), AuthServiceError>;
    async fn delete_session_token(&self, user_id: &UserId) -> Result<(), AuthServiceError>;
    async fn create_csrf_token(
        &self,
    ) -> Result<(CsrfToken, time::OffsetDateTime), AuthServiceError>;
    async fn get_user_profile(&self, user_id: &UserId) -> Result<UserProfile, AuthServiceError>;
}

#[derive(Debug, Clone)]
pub enum AuthServiceError {
    InternalError(String, String),
    RegistrationNotAllowed(String, String),
    ConnectivityProblem(String, String),
    UserAlreadyExists(String, String),
    InvalidOneTimeToken(String, String),
    Unauthorized(String, String),
    InvalidCsrfToken(String, String),
}

impl std::fmt::Display for AuthServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error = match self {
            AuthServiceError::InternalError(eid, details) => {
                format!("eid: {}, slogan: Internal Error, details: {}", eid, details)
            }
            AuthServiceError::RegistrationNotAllowed(eid, details) => format!(
                "eid: {}, slogan: Registration not allowed, details: {}",
                eid, details
            ),
            AuthServiceError::ConnectivityProblem(eid, details) => format!(
                "eid: {}, slogan: Connectivity problem, details: {}",
                eid, details
            ),
            AuthServiceError::UserAlreadyExists(eid, details) => format!(
                "eid: {}, slogan: User does already exists, details: {}",
                eid, details
            ),
            AuthServiceError::InvalidOneTimeToken(eid, details) => format!(
                "eid: {}, slogan: Invalid one time token, details: {}",
                eid, details
            ),
            AuthServiceError::Unauthorized(eid, details) => {
                format!("eid: {}, slogan: Unauthorized, details: {}", eid, details)
            }
            AuthServiceError::InvalidCsrfToken(eid, details) => {
                format!("eid: {}, slogan: Unauthorized, details: {}", eid, details)
            }
        };
        f.write_str(&error)
    }
}

impl AuthServiceError {
    pub fn eid(&self) -> &String {
        match self {
            AuthServiceError::InternalError(eid, _) => eid,
            AuthServiceError::RegistrationNotAllowed(eid, _) => eid,
            AuthServiceError::ConnectivityProblem(eid, _) => eid,
            AuthServiceError::UserAlreadyExists(eid, _) => eid,
            AuthServiceError::InvalidOneTimeToken(eid, _) => eid,
            AuthServiceError::Unauthorized(eid, _) => eid,
            AuthServiceError::InvalidCsrfToken(eid, _) => eid,
        }
    }
}
