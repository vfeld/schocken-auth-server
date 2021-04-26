use super::auth_config_port::AuthConfigPort;

use std::env;
#[derive(Clone, Debug)]
pub struct AuthConfigEnvAdapter {}
impl AuthConfigEnvAdapter {
    pub fn new() -> Self {
        AuthConfigEnvAdapter {}
    }
}
#[async_trait::async_trait]
impl AuthConfigPort for AuthConfigEnvAdapter {
    async fn day0_token_lifetime(&self) -> time::Duration {
        let lifetime_seconds = env::var("DAY0_TOKEN_LIFETIME_SECONDS")
            .unwrap_or("300".into())
            .parse::<u32>()
            .expect("DAY0_TOKEN_LIFETIME_SECONDS needs to be a number");
        time::Duration::second() * lifetime_seconds
    }

    async fn day0_token(&self) -> String {
        env::var("DAY0_TOKEN").expect("A day0 token must be set")
    }

    async fn db_host(&self) -> String {
        env::var("DB_HOST").unwrap_or("localhost".into())
    }

    async fn db_port(&self) -> u16 {
        env::var("DB_PORT")
            .unwrap_or("5432".into())
            .parse::<u16>()
            .expect("DB_PORT must be a number")
    }

    async fn db_user(&self) -> String {
        env::var("DB_USER").expect("DB_USER must be set")
    }

    async fn db_pwd(&self) -> String {
        env::var("DB_PWD").expect("DB_PWD must be set")
    }

    async fn db_name(&self) -> String {
        env::var("DB_NAME").unwrap_or("schocken".into())
    }

    async fn host(&self) -> String {
        env::var("HOST").unwrap_or("localhost".into())
    }

    async fn port(&self) -> u16 {
        env::var("PORT")
            .unwrap_or("8080".into())
            .parse::<u16>()
            .expect("PORT must be a number")
    }

    async fn session_lifetime(&self) -> time::Duration {
        let lifetime_minutes = env::var("SESSION_LIFETIME_MINUTES")
            .unwrap_or("60".into())
            .parse::<u32>()
            .expect("SESSION_LIFETIME_MINUTES needs to be a number");
        time::Duration::minute() * lifetime_minutes
    }

    async fn jwt_signing_secret(&self) -> String {
        env::var("JWT_SIGNING_SECRET").expect("A JWT signing secret must be set")
    }
}
