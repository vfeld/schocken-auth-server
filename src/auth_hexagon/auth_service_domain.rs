use base64;
use log::error;
use std::convert::TryFrom;

use super::auth_service_port::*;
use super::auth_store_port::*;
use super::auth_types::*;

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::pwhash;
#[cfg(test)]
pub mod test_csrf;
#[cfg(test)]
pub mod test_session;

#[derive(Clone, Debug)]
pub struct AuthServiceDomain<A: AuthStorePort> {
    auth_store: A,
    day0_token_lifetime: time::Duration,
    session_lifetime: time::Duration,
    jwt_signing_secret: String,
}

impl<A> AuthServiceDomain<A>
where
    A: AuthStorePort + Send + Sync,
{
    pub fn new(
        store: A,
        day0_token_lifetime: time::Duration,
        session_lifetime: time::Duration,
        jwt_signing_secret: String,
    ) -> Self {
        AuthServiceDomain {
            auth_store: store,
            day0_token_lifetime,
            session_lifetime,
            jwt_signing_secret,
        }
    }
}

#[async_trait::async_trait]
impl<A> AuthServicePort for AuthServiceDomain<A>
where
    A: AuthStorePort + Send + Sync,
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
        let lifetime = self.day0_token_lifetime;
        let roles: Vec<Role> = vec![Role::Default, Role::Admin];
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
    ) -> Result<(SessionToken, time::OffsetDateTime), AuthServiceError> {
        let session_lifetime = self.session_lifetime;

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
            &EncodingKey::from_secret(self.jwt_signing_secret.as_ref()),
        )
        .unwrap();
        self.auth_store
            .set_session_id(&user_id, &session_id)
            .await?;

        Ok((SessionToken(token), now + session_lifetime))
    }

    async fn auth_session_token(
        &self,
        session_token: &SessionToken,
    ) -> Result<(UserId, time::OffsetDateTime), AuthServiceError> {
        match decode::<SessionTokenClaims>(
            &session_token.0,
            &DecodingKey::from_secret(self.jwt_signing_secret.as_ref()),
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
                    Ok(Some(user_id)) => {
                        let expiry = time::OffsetDateTime::from_unix_timestamp(
                            i64::try_from(claims.exp).unwrap(),
                        );
                        return Ok((user_id, expiry));
                    }
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

    async fn create_csrf_token(
        &self,
    ) -> Result<(CsrfToken, time::OffsetDateTime), AuthServiceError> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).unwrap();
        let lifetime = self.session_lifetime;
        let now = time::OffsetDateTime::now_utc();

        Ok((
            base64::encode(hash::sha256::hash(&buf).as_ref()),
            now + lifetime,
        ))
    }

    async fn get_user_profile(&self, user_id: &UserId) -> Result<UserProfile, AuthServiceError> {
        self.auth_store
            .get_user_profile(user_id)
            .await
            .map_err(|e| e.into())
    }
}
