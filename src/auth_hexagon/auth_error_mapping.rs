use super::auth_service_port::*;
use super::auth_store_port::*;

impl core::convert::From<AuthStoreError> for AuthServiceError {
    fn from(e: AuthStoreError) -> Self {
        match e {
            AuthStoreError::ConnectivityProblem(eid, details) => {
                AuthServiceError::ConnectivityProblem(eid, details)
            }
            AuthStoreError::InternalProblem(eid, details) => {
                AuthServiceError::InternalError(eid, details)
            }
            AuthStoreError::MisConfiguration(eid, details) => {
                AuthServiceError::InternalError(eid, details)
            }
            AuthStoreError::InvalidOneTimeToken(eid, details) => {
                AuthServiceError::InvalidOneTimeToken(eid, details)
            }
            AuthStoreError::DataNotFound(eid, details) => {
                AuthServiceError::InternalError(eid, details)
            }
            AuthStoreError::DataNotUnique(eid, details) => {
                AuthServiceError::InternalError(eid, details)
            }
            AuthStoreError::InvalidSessionId(eid, details) => {
                AuthServiceError::Unauthorized(eid, details)
            }
        }
    }
}

impl core::convert::From<AuthServiceError> for Box<dyn std::error::Error> {
    fn from(e: AuthServiceError) -> Self {
        return e.to_string().into();
    }
}
