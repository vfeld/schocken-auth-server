use super::auth_store_port::*;
use super::auth_types::*;
use sqlx::postgres::Postgres;
use sqlx::{migrate, Pool};

use std::sync::Arc;

use log::error;

pub mod pg_error_mapping;
pub mod pg_queries;

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
        credential: &Credential,
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
        pg_queries::insert_credential(pool.clone(), user_id, credential).await?;
        pg_queries::insert_user_profile(pool.clone(), user_id, user).await?;
        pg_queries::insert_roles(pool.clone(), user_id, &roles).await?;
        pg_queries::invalidate_day0_token(pool.clone(), token).await?;

        tx.commit().await?;
        Ok(user_id)
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

    use uuid::Uuid;

    use super::*;
    async fn init(test_name: &str) -> Box<dyn AuthStorePort> {
        dotenv::dotenv().ok();

        let _ = env_logger::builder().is_test(true).try_init();
        let db_user = std::env::var("DB_USER").unwrap_or("pgadmin".into());
        let db_pwd = std::env::var("DB_PWD").unwrap_or("secret".into());
        let db_host = std::env::var("DB_HOST").unwrap_or("localhost".into());
        let db_port = std::env::var("DB_PORT").unwrap_or("5432".into());
        let db_name = std::env::var("DB_NAME").unwrap_or("schocken".into());
        let test_exe_id = Uuid::new_v4().to_string().replace("-", "");

        let test_db_name = format!("{}_{}", test_name, test_exe_id);
        let name = if test_db_name.len() > 63 {
            &test_db_name[..63]
        } else {
            &test_db_name[..]
        };
        println!("DB Name: {}", name);
        AuthStorePgAdapter::create_db(&db_user, &db_pwd, &db_host, &db_port, &db_name, &name)
            .await
            .unwrap();
        let store = AuthStorePgAdapter::new(&db_user, &db_pwd, &db_host, &db_port, &name).await;
        Box::new(store)
    }

    #[actix_web::main]
    #[test]
    async fn test_day0_registration_success() {
        let store = init("test_day0_registration_success").await;

        let user = UserProfile {
            first_name: "John".into(),
            last_name: "Doe".into(),
            email: "john.doe@example.local".into(),
        };
        let cred = Credential {
            login_name: "john.doe@example.local".into(),
            password: "12345678".into(),
        };
        let roles = vec![Roles::Admin, Roles::Default];
        let token: Token = "1234567890".into();
        let lifetime = time::Duration::second();

        let result = store.set_day0_token(&token).await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }

        let result = store
            .day0_registration(&user, &cred, roles, &token, lifetime)
            .await;
        match result {
            Ok(_id) => assert!(true),
            Err(_e) => assert!(false),
        }
    }

    #[actix_web::main]
    #[test]
    async fn test_set_day0_token_twice() {
        let store = init("test_set_day0_token_twice").await;

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
        let store = init("test_day0_registration_with_unknown_token").await;

        let user = UserProfile {
            first_name: "John".into(),
            last_name: "Doe".into(),
            email: "john.doe@example.local".into(),
        };
        let cred = Credential {
            login_name: "john.doe@example.local".into(),
            password: "12345678".into(),
        };
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
            .day0_registration(&user, &cred, roles, &token_invalid, lifetime)
            .await;
        match result {
            Ok(_id) => assert!(false),
            Err(e) => match e {
                AuthStoreError::InvalidOneTimeToken(_, _) => assert!(true),
                _ => assert!(false),
            },
        }
    }
}
