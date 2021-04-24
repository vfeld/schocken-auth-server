use log::error;

use super::auth_config_port::*;
use super::auth_service_port::*;
use super::auth_store_port::*;
use super::auth_types::*;

use sodiumoxide::crypto::pwhash;

#[derive(Clone, Debug)]
pub struct AuthServiceDomain<A: AuthStorePort, B: AuthConfigPort> {
    auth_store: A,
    auth_config: B,
}

impl<A, B> AuthServiceDomain<A, B>
where
    A: AuthStorePort + Send + Sync,
    B: AuthConfigPort + Send + Sync,
{
    pub fn new(store: A, config: B) -> Self {
        AuthServiceDomain {
            auth_store: store,
            auth_config: config,
        }
    }
}

#[async_trait::async_trait]
impl<A, B> AuthServicePort for AuthServiceDomain<A, B>
where
    A: AuthStorePort + Send + Sync,
    B: AuthConfigPort + Send + Sync,
{
    async fn set_day0_token(&self, token: &Token) -> Result<(), AuthServiceError> {
        match self.auth_store.set_day0_token(token).await {
            Ok(_) => Ok(()),
            Err(err) => {
                error!("eid: {}, error in setting day0 token", err.eid());
                Err(err.into())
            }
        }
    }

    async fn day0_registration(
        &self,
        user_profile: &UserProfile,
        credential: &Credential,
        token: &Token,
    ) -> Result<UserId, AuthServiceError> {
        let lifetime = self.auth_config.day0_token_lifetime().await;
        let roles: Vec<Roles> = vec![Roles::Default, Roles::Admin];
        let pwh = pwhash::pwhash(&credential.password.clone().into_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE).unwrap();
        match self
            .auth_store
            .day0_registration(user_profile, &credential.login_name,pwh.as_ref(), roles, token, lifetime)
            .await
        {
            Ok(id) => Ok(id),
            Err(err) => {
                error!("eid: {}, error in day0 registration", err.eid());
                Err(err.into())
            }
        }
    }

    async fn auth_credential(
        &self,
        credential: &Credential,
    ) -> Result<UserId, AuthServiceError> {
        match self
        .auth_store
        .get_pwd_hash(&credential.login_name)
        .await
        {
            Ok((uid,pwd_hash)) => {
                if pwhash::pwhash_verify(&pwhash::HashedPassword::from_slice(&pwd_hash[..]).unwrap(), &credential.password.clone().into_bytes()){
                    Ok(uid)
                } else {
                    let uuid = uuid::Uuid::new_v4();
                    let details = format!("wrong password for user: {}",credential.login_name);
                    let eid = uuid.to_string();
                    error!("eid: {}, {}", eid,details);
                    Err(AuthServiceError::Unauthorized(eid,details))
                }
            }
            Err(err) => {
                match  err {
                    AuthStoreError::DataNotFound(eid,details) => {
                        let uuid = uuid::Uuid::new_v4();
                        let details = format!("wrong password for user: {}",credential.login_name);
                        let eid = uuid.to_string();
                        error!("eid: {}, {}", eid,details);
                        Err(AuthServiceError::Unauthorized(eid,details))
                    }
                    _ => {
                        error!("eid: {}, error in authentication using user: {}", err.eid(),credential.login_name);
                        Err(err.into())
                    }
                }
            }
        }
    }
}
