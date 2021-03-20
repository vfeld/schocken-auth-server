use super::auth_service_port::*;
use super::auth_store_port::*;

impl core::convert::From<AuthStoreError> for AuthServiceError {
    fn from(e: AuthStoreError) -> Self {
        match e {
            AuthStoreError::ConnectivityProblem(eid, details) => {
                AuthServiceError::ConnectivityProblem(eid, details)
            }
            AuthStoreError::InternalProblem(eid, details) => {
                AuthServiceError::RegistrationNotAllowed(eid, details)
            }
            AuthStoreError::MisConfiguration(eid, details) => {
                AuthServiceError::RegistrationNotAllowed(eid, details)
            }
            AuthStoreError::InvalidOneTimeToken(eid, details) => {
                AuthServiceError::InvalidOneTimeToken(eid, details)
            }
        }
    }
}

impl core::convert::From<AuthServiceError> for Box<dyn std::error::Error> {
    fn from(e: AuthServiceError) -> Self {
        return e.to_string().into();
    }
}
