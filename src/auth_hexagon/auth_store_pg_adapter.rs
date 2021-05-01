use super::auth_store_port::*;
use super::auth_types::*;
use sqlx::postgres::Postgres;
use sqlx::{migrate, Pool};

use std::sync::Arc;

use log::error;

pub mod pg_error_mapping;
pub mod pg_queries;
pub mod pg_queries_credential;
pub mod pg_queries_session;
#[cfg(test)]
pub mod test_utils;

#[derive(Clone, Debug)]
pub struct AuthStorePgAdapter {
    pub pool: Arc<Pool<Postgres>>,
}

impl AuthStorePgAdapter {
    pub async fn new(
        db_user: &str,
        db_pwd: &str,
        db_host: &str,
        db_port: &str,
        db_name: &str,
    ) -> Self {
        //Perform migrations
        let db_url = format!(
            "postgres://{}:{}@{}:{}/{}",
            db_user, db_pwd, db_host, db_port, db_name
        );

        //Connect to the DB
        let pool: Pool<Postgres> = Pool::connect(&db_url)
            .await
            .expect("DB connection can not be established");

        migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to migrate the database");

        AuthStorePgAdapter {
            pool: Arc::new(pool),
        }
    }
    #[cfg(test)]
    pub async fn create_db(
        db_user: &str,
        db_pwd: &str,
        db_host: &str,
        db_port: &str,
        db_name: &str,
        test_db_name: &str,
    ) -> Result<(), AuthStoreError> {
        //Perform migrations
        let db = format!(
            "postgres://{}:{}@{}:{}/{}",
            db_user, db_pwd, db_host, db_port, db_name
        );

        //Connect to the DB
        let pool: Pool<Postgres> = Pool::connect(&db)
            .await
            .expect("DB connection can not be established");

        let sql = format!("CREATE DATABASE {};", test_db_name);
        let _res = sqlx::query(&sql).execute(&pool).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuthStorePort for AuthStorePgAdapter {
    async fn set_day0_token(&self, token: &Token) -> Result<(), AuthStoreError> {
        let pool = self.pool.clone();
        let tx = pool.begin().await?;

        pg_queries::has_token(pool.clone(), token).await?;
        pg_queries::insert_day0_token(pool.clone(), token).await?;

        tx.commit().await?;
        Ok(())
    }

    async fn day0_registration(
        &self,
        user: &UserProfile,
        login_name: &str,
        password_hash: &[u8],
        roles: Vec<Roles>,
        token: &super::auth_types::Token,
        lifetime: time::Duration,
    ) -> Result<UserId, AuthStoreError> {
        let now = time::OffsetDateTime::now_utc();

        let pool = self.pool.clone();
        let tx = pool.begin().await?;

        let created_at = pg_queries::get_day0_token_data(pool.clone(), token).await?;

        if (created_at + lifetime) < now {
            let uuid = uuid::Uuid::new_v4();
            let details = "day0 token is expired";
            error!("eid: {}, details: {}", uuid, details);
            return Err(AuthStoreError::InvalidOneTimeToken(
                uuid.to_string(),
                details.into(),
            ));
        }

        let user_id = pg_queries::create_user_id(pool.clone()).await?;
        pg_queries::insert_credential(pool.clone(), user_id.clone(), login_name, password_hash)
            .await?;
        pg_queries::insert_user_profile(pool.clone(), user_id.clone(), user).await?;
        pg_queries::insert_roles(pool.clone(), user_id.clone(), &roles).await?;
        pg_queries::invalidate_day0_token(pool.clone(), token).await?;

        tx.commit().await?;
        Ok(user_id)
    }

    async fn get_pwd_hash(&self, login_name: &str) -> Result<(UserId, Vec<u8>), AuthStoreError> {
        let pool = self.pool.clone();
        pg_queries_credential::get_pwd_hash(pool.clone(), login_name).await
    }

    async fn set_session_id(
        &self,
        user_id: &UserId,
        session_id: &str,
    ) -> Result<(), AuthStoreError> {
        let pool = self.pool.clone();
        let tx = pool.begin().await?;
        match pg_queries_session::find_user_id_by_session_id(pool.clone(), session_id).await? {
            Some(found_user_id) => {
                if &found_user_id != user_id {
                    let uuid = uuid::Uuid::new_v4();
                    let details = "session id, user_id mismatch";
                    error!("eid: {}, details: {}", uuid, details);
                    return Err(AuthStoreError::InvalidSessionId(
                        uuid.to_string(),
                        details.into(),
                    ));
                }
                pg_queries_session::delete_session(pool.clone(), user_id).await?;
            }
            None => {}
        }
        pg_queries_session::insert_session_id(pool.clone(), user_id, session_id).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get_user_id_by_session_id(
        &self,
        session_id: &str,
    ) -> Result<Option<UserId>, AuthStoreError> {
        let pool = self.pool.clone();
        pg_queries_session::find_user_id_by_session_id(pool.clone(), session_id).await
    }

    async fn delete_session_id(&self, user_id: &UserId) -> Result<(), AuthStoreError> {
        let pool = self.pool.clone();
        pg_queries_session::delete_session(pool.clone(), user_id).await
    }
}

impl core::convert::From<sqlx::Error> for AuthStoreError {
    fn from(e: sqlx::Error) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let details = e.to_string();
        match e {
            sqlx::Error::Configuration(_s) => {
                AuthStoreError::MisConfiguration(uuid.to_string(), details)
            }
            sqlx::Error::Database(_s) => AuthStoreError::InternalProblem(uuid.to_string(), details),
            sqlx::Error::Io(_s) => AuthStoreError::ConnectivityProblem(uuid.to_string(), details),
            sqlx::Error::Tls(_s) => AuthStoreError::ConnectivityProblem(uuid.to_string(), details),
            sqlx::Error::Protocol(_s) => AuthStoreError::InternalProblem(uuid.to_string(), details),
            sqlx::Error::RowNotFound => {
                AuthStoreError::InternalProblem(uuid.to_string(), e.to_string())
            }
            sqlx::Error::ColumnIndexOutOfBounds { index: _, len: _ } => {
                AuthStoreError::InternalProblem(uuid.to_string(), details)
            }
            sqlx::Error::ColumnNotFound(_s) => {
                AuthStoreError::InternalProblem(uuid.to_string(), details)
            }
            sqlx::Error::ColumnDecode {
                index: _,
                source: _,
            } => AuthStoreError::InternalProblem(uuid.to_string(), details),
            sqlx::Error::Decode(_s) => AuthStoreError::InternalProblem(uuid.to_string(), details),
            sqlx::Error::PoolTimedOut => {
                AuthStoreError::ConnectivityProblem(uuid.to_string(), details)
            }
            sqlx::Error::PoolClosed => {
                AuthStoreError::ConnectivityProblem(uuid.to_string(), details)
            }
            sqlx::Error::WorkerCrashed => {
                AuthStoreError::ConnectivityProblem(uuid.to_string(), details)
            }
            sqlx::Error::Migrate(_s) => AuthStoreError::InternalProblem(uuid.to_string(), details),
            _ => AuthStoreError::InternalProblem(uuid.to_string(), details),
        }
    }
}

#[cfg(test)]
mod tests {

    use sodiumoxide::crypto::pwhash;
    use test_utils::pg_store_init;

    use super::*;

    #[actix_web::main]
    #[test]
    async fn test_day0_registration_success() {
        let store = pg_store_init("test_day0_registration_success").await;

        let user = UserProfile {
            first_name: "John".into(),
            last_name: "Doe".into(),
            email: "john.doe@example.local".into(),
        };
        let cred = Credential {
            login_name: "john.doe@example.local".into(),
            password: "12345678".into(),
        };
        let pwh = pwhash::pwhash(
            &cred.password.clone().into_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let roles = vec![Roles::Admin, Roles::Default];
        let token: Token = "1234567890".into();
        let lifetime = time::Duration::second() * 60;

        let result = store.set_day0_token(&token).await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }

        let result = store
            .day0_registration(
                &user,
                &cred.login_name,
                pwh.as_ref(),
                roles,
                &token,
                lifetime,
            )
            .await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }
    }

    #[actix_web::main]
    #[test]
    async fn test_set_day0_token_twice() {
        let store = pg_store_init("test_set_day0_token_twice").await;

        let token: Token = "1234567890".into();

        let result = store.set_day0_token(&token).await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }

        let result = store.set_day0_token(&token).await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }
    }
    #[actix_web::main]
    #[test]
    async fn test_day0_registration_with_unknown_token() {
        let store = pg_store_init("test_day0_registration_with_unknown_token").await;

        let user = UserProfile {
            first_name: "John".into(),
            last_name: "Doe".into(),
            email: "john.doe@example.local".into(),
        };
        let cred = Credential {
            login_name: "john.doe@example.local".into(),
            password: "12345678".into(),
        };
        let pwh = pwhash::pwhash(
            &cred.password.clone().into_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        let roles = vec![Roles::Admin, Roles::Default];
        let token: Token = "1234567890".into();
        let token_invalid: Token = "1234567891".into();

        let lifetime = time::Duration::second();

        let result = store.set_day0_token(&token).await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }

        let result = store
            .day0_registration(
                &user,
                &cred.login_name,
                pwh.as_ref(),
                roles,
                &token_invalid,
                lifetime,
            )
            .await;
        match result {
            Ok(_id) => assert!(false),
            Err(e) => match e {
                AuthStoreError::InvalidOneTimeToken(_, _) => assert!(true),
                _ => assert!(false),
            },
        }
    }
    #[actix_web::main]
    #[test]
    async fn test_auth_password() {
        let store = pg_store_init("test_auth_password").await;

        let user = UserProfile {
            first_name: "John".into(),
            last_name: "Doe".into(),
            email: "john.doe@example.local".into(),
        };
        let cred = Credential {
            login_name: "john.doe@example.local".into(),
            password: "12345678".into(),
        };
        let pwh = pwhash::pwhash(
            &cred.password.clone().into_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let roles = vec![Roles::Admin, Roles::Default];
        let token: Token = "1234567890".into();
        let lifetime = time::Duration::second() * 60;

        let result = store.set_day0_token(&token).await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }

        let result = store
            .day0_registration(
                &user,
                &cred.login_name,
                pwh.as_ref(),
                roles,
                &token,
                lifetime,
            )
            .await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }

        let result = store.get_pwd_hash(&cred.login_name).await;
        let pwd_hash = match result {
            Ok((_uid, pwd_hash)) => pwd_hash,
            Err(_e) => {
                assert!(false);
                return;
            }
        };
        let result = pwhash::pwhash_verify(
            &pwhash::HashedPassword::from_slice(&pwd_hash[..]).unwrap(),
            cred.password.clone().as_bytes(),
        );
        assert!(result);

        let result = pwhash::pwhash_verify(
            &pwhash::HashedPassword::from_slice(&pwd_hash[..]).unwrap(),
            "wrong password".as_bytes(),
        );
        assert!(!result);

        let result = store.get_pwd_hash(&"unknown user").await;
        match result {
            Ok((_, _)) => assert!(false),
            Err(AuthStoreError::DataNotFound(_, _)) => {
                assert!(true);
            }
            _ => assert!(false),
        };
    }

    #[actix_web::main]
    #[test]
    async fn test_session() {
        let store = pg_store_init("test_session").await;
        match store.set_session_id(&UserId(5), "s1").await {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match store.get_user_id_by_session_id("s0").await {
            Ok(Some(_)) => assert!(false),
            Ok(None) => assert!(true),
            Err(_) => assert!(false),
        }
        match store.get_user_id_by_session_id("s1").await {
            Ok(Some(u)) => {
                if u == UserId(5) {
                    assert!(true)
                } else {
                    assert!(false)
                }
            }
            Ok(None) => assert!(false),
            Err(_) => assert!(false),
        }
        match store.delete_session_id(&UserId(1)).await {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match store.delete_session_id(&UserId(5)).await {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match store.get_user_id_by_session_id("s1").await {
            Ok(Some(_)) => assert!(false),
            Ok(None) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}
