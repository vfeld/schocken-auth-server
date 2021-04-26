use mock_it::Matcher;
use mock_it::Mock;

use super::auth_service_port::AuthServicePort;
use super::auth_types::*;
use async_trait::async_trait;

#[derive(Clone)]
pub struct AuthServiceMock {
    pub set_day0_token:
        Mock<Matcher<Token>, Result<(), super::auth_service_port::AuthServiceError>>,
    pub day0_registration: Mock<
        Matcher<(UserProfile, Credential, Token)>,
        Result<UserId, super::auth_service_port::AuthServiceError>,
    >,
    pub auth_credential:
        Mock<Matcher<Credential>, Result<UserId, super::auth_service_port::AuthServiceError>>,
    pub create_session_token:
        Mock<Matcher<UserId>, Result<SessionToken, super::auth_service_port::AuthServiceError>>,
    pub auth_session_token:
        Mock<Matcher<SessionToken>, Result<UserId, super::auth_service_port::AuthServiceError>>,
    pub delete_session_token:
        Mock<Matcher<UserId>, Result<(), super::auth_service_port::AuthServiceError>>,
}

#[async_trait]
impl AuthServicePort for AuthServiceMock {
    async fn set_day0_token(
        &self,
        token: &Token,
    ) -> Result<(), super::auth_service_port::AuthServiceError> {
        self.set_day0_token.called(Matcher::Val(token.clone()))
    }

    async fn day0_registration(
        &self,
        user: &UserProfile,
        credential: &Credential,
        token: &Token,
    ) -> Result<UserId, super::auth_service_port::AuthServiceError> {
        self.day0_registration.called(Matcher::Val((
            user.clone(),
            credential.clone(),
            token.clone(),
        )))
    }

    async fn auth_credential(
        &self,
        credential: &Credential,
    ) -> Result<UserId, super::auth_service_port::AuthServiceError> {
        self.auth_credential
            .called(Matcher::Val(credential.clone()))
    }

    async fn create_session_token(
        &self,
        user_id: &UserId,
    ) -> Result<SessionToken, super::auth_service_port::AuthServiceError> {
        self.create_session_token
            .called(Matcher::Val(user_id.clone()))
    }

    async fn auth_session_token(
        &self,
        session_token: &SessionToken,
    ) -> Result<UserId, super::auth_service_port::AuthServiceError> {
        self.auth_session_token
            .called(Matcher::Val(session_token.clone()))
    }
    async fn delete_session_token(
        &self,
        user_id: &UserId,
    ) -> Result<(), super::auth_service_port::AuthServiceError> {
        self.delete_session_token
            .called(Matcher::Val(user_id.clone()))
    }
}

impl AuthServiceMock {
    pub fn new() -> Self {
        AuthServiceMock {
            set_day0_token: Mock::new(Ok(())),
            day0_registration: Mock::new(Ok(0)),
            auth_credential: Mock::new(Ok(0)),
            create_session_token: Mock::new(Ok("".into())),
            auth_session_token: Mock::new(Ok(0)),
            delete_session_token: Mock::new(Ok(())),
        }
    }
}
