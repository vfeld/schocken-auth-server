use base64;
use log::error;
use std::convert::TryFrom;

use super::auth_config_port::*;
use super::auth_service_port::*;
use super::auth_store_port::*;
use super::auth_types::*;

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sodiumoxide::crypto::hash;
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
        let pwh = pwhash::pwhash(
            &credential.password.clone().into_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        match self
            .auth_store
            .day0_registration(
                user_profile,
                &credential.login_name,
                pwh.as_ref(),
                roles,
                token,
                lifetime,
            )
            .await
        {
            Ok(id) => Ok(id),
            Err(err) => {
                error!("eid: {}, error in day0 registration", err.eid());
                Err(err.into())
            }
        }
    }

    async fn auth_credential(&self, credential: &Credential) -> Result<UserId, AuthServiceError> {
        match self.auth_store.get_pwd_hash(&credential.login_name).await {
            Ok((uid, pwd_hash)) => {
                if pwhash::pwhash_verify(
                    &pwhash::HashedPassword::from_slice(&pwd_hash[..]).unwrap(),
                    &credential.password.clone().into_bytes(),
                ) {
                    Ok(uid)
                } else {
                    let uuid = uuid::Uuid::new_v4();
                    let details = format!("wrong password for user: {}", credential.login_name);
                    let eid = uuid.to_string();
                    error!("eid: {}, {}", eid, details);
                    Err(AuthServiceError::Unauthorized(eid, details))
                }
            }
            Err(err) => match err {
                AuthStoreError::DataNotFound(eid, _details) => {
                    let details = format!("wrong password for user: {}", credential.login_name);
                    error!("eid: {}, {}", eid, details);
                    Err(AuthServiceError::Unauthorized(eid, details))
                }
                _ => {
                    error!(
                        "eid: {}, error in authentication using user: {}",
                        err.eid(),
                        credential.login_name
                    );
                    Err(err.into())
                }
            },
        }
    }

    async fn create_session_token(
        &self,
        user_id: &UserId,
    ) -> Result<SessionToken, AuthServiceError> {
        let secret = self.auth_config.jwt_signing_secret().await;
        let session_lifetime = self.auth_config.session_lifetime().await;

        let now = time::OffsetDateTime::now_utc();
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).unwrap();
        let session_id = base64::encode(hash::sha256::hash(&buf).as_ref());

        let session_token_claims = SessionTokenClaims {
            iss: "schocken-auth-server".into(),
            aud: "schocken-auth-server/session".into(),
            sub: session_id.clone(),
            iat: usize::try_from(now.unix_timestamp()).unwrap(),
            exp: usize::try_from((now + session_lifetime).unix_timestamp()).unwrap(),
        };
        let token = encode(
            &Header::default(),
            &session_token_claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )
        .unwrap();
        self.auth_store
            .set_session_id(&user_id, &session_id)
            .await?;

        Ok(token)
    }

    async fn auth_session_token(
        &self,
        session_token: &SessionToken,
    ) -> Result<UserId, AuthServiceError> {
        let secret = self.auth_config.jwt_signing_secret().await;
        match decode::<SessionTokenClaims>(
            &session_token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        ) {
            Ok(token_data) => {
                let claims = token_data.claims;
                if claims.iss != "schocken-auth-server" {
                    let uuid = uuid::Uuid::new_v4();
                    let details =
                        format!("invalid session token: {}, {}", "wrong issuer", claims.iss);
                    let eid = uuid.to_string();
                    error!("eid: {}, {}", eid, details);
                    return Err(AuthServiceError::Unauthorized(eid, details));
                }
                if claims.aud != "schocken-auth-server/session" {
                    let uuid = uuid::Uuid::new_v4();
                    let details = format!(
                        "invalid session token: {}, {}",
                        "wrong audience", claims.aud
                    );
                    let eid = uuid.to_string();
                    error!("eid: {}, {}", eid, details);
                    return Err(AuthServiceError::Unauthorized(eid, details));
                }
                match self.auth_store.get_user_id_by_session_id(&claims.sub).await {
                    Ok(Some(user_id)) => return Ok(user_id),
                    Ok(None) => {
                        let uuid = uuid::Uuid::new_v4();
                        let details = format!(
                            "invalid session token: {}, {}",
                            "wrong session_id", claims.sub
                        );
                        let eid = uuid.to_string();
                        error!("eid: {}, {}", eid, details);
                        return Err(AuthServiceError::Unauthorized(eid, details));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => {
                let uuid = uuid::Uuid::new_v4();
                let details = format!("invalid session token: {}", e.to_string());
                let eid = uuid.to_string();
                error!("eid: {}, {}", eid, details);
                return Err(AuthServiceError::Unauthorized(eid, details));
            }
        }
    }

    async fn delete_session_token(&self, user_id: &UserId) -> Result<(), AuthServiceError> {
        self.auth_store.delete_session_id(user_id).await?;

        Ok(())
    }
}
