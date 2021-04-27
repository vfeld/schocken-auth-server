use mock_it::Matcher;
use mock_it::Mock;

use super::auth_store_port::*;
use super::auth_types::*;

use async_trait::async_trait;

#[derive(Clone)]
pub struct AuthStoreMock {
    pub set_day0_token: Mock<Matcher<Token>, Result<(), super::auth_store_port::AuthStoreError>>,
    pub day0_registration: Mock<
        Matcher<(
            UserProfile,
            String,
            Vec<u8>,
            Vec<Roles>,
            Token,
            time::Duration,
        )>,
        Result<UserId, super::auth_store_port::AuthStoreError>,
    >,
    pub get_pwd_hash:
        Mock<Matcher<String>, Result<(UserId, Vec<u8>), super::auth_store_port::AuthStoreError>>,
    pub set_session_id:
        Mock<Matcher<(UserId, String)>, Result<(), super::auth_store_port::AuthStoreError>>,
    pub get_user_id_by_session_id:
        Mock<Matcher<String>, Result<Option<UserId>, super::auth_store_port::AuthStoreError>>,
    pub delete_session_id:
        Mock<Matcher<UserId>, Result<(), super::auth_store_port::AuthStoreError>>,
}

impl AuthStoreMock {
    pub fn new() -> Self {
        AuthStoreMock {
            set_day0_token: Mock::new(Ok(())),
            day0_registration: Mock::new(Ok(0)),
            get_pwd_hash: Mock::new(Ok((0, vec![]))),
            set_session_id: Mock::new(Ok(())),
            get_user_id_by_session_id: Mock::new(Ok(None)),
            delete_session_id: Mock::new(Ok(())),
        }
    }
}

#[async_trait]
impl AuthStorePort for AuthStoreMock {
    async fn set_day0_token(&self, token: &Token) -> Result<(), AuthStoreError> {
        self.set_day0_token.called(Matcher::Val(token.clone()))
    }

    async fn day0_registration(
        &self,
        user: &UserProfile,
        login_name: &str,
        password_hash: &[u8],
        roles: Vec<Roles>,
        token: &Token,
        lifetime: time::Duration,
    ) -> Result<UserId, AuthStoreError> {
        self.day0_registration.called(Matcher::Val((
            user.clone(),
            login_name.to_string(),
            Vec::from(password_hash),
            roles,
            token.clone(),
            lifetime,
        )))
    }

    async fn get_pwd_hash(&self, login_name: &str) -> Result<(UserId, Vec<u8>), AuthStoreError> {
        self.get_pwd_hash
            .called(Matcher::Val(login_name.to_string()))
    }

    async fn set_session_id(
        &self,
        user_id: &UserId,
        session_id: &str,
    ) -> Result<(), AuthStoreError> {
        self.set_session_id
            .called(Matcher::Val((user_id.clone(), session_id.to_string())))
    }

    async fn get_user_id_by_session_id(
        &self,
        session_id: &str,
    ) -> Result<Option<UserId>, AuthStoreError> {
        self.get_user_id_by_session_id
            .called(Matcher::Val(session_id.to_string()))
    }

    async fn delete_session_id(&self, user_id: &UserId) -> Result<(), AuthStoreError> {
        self.delete_session_id.called(Matcher::Val(user_id.clone()))
    }
}
