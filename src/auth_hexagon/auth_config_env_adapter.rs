use super::auth_config_port::AuthConfigPort;
use super::auth_types::TlsConfig;

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

    async fn allowed_origin(&self) -> String {
        env::var("ALLOWED_ORIGIN").expect("ALLOWED_ORIGIN must be set")
    }

    async fn tls_server_config(&self) -> Option<TlsConfig> {
        let msg = r#"ENABLE_TLS must be set to true or false.
        If set to true the variables SERVER_KEY_PEMFILE and SERVER_CERT_PEMFILE
        have to be set to filenames pointing to server certificate and key
        files in pem format"#;
        let enable_tls = env::var("ENABLE_TLS")
            .expect(msg)
            .parse::<bool>()
            .expect(msg);
        if !enable_tls {
            return None;
        };
        let key = env::var("SERVER_KEY_PEMFILE").expect(
            r#"When ENABLE_TLS is set to true the 
        SERVER_KEY_PEMFILE must be set to a filename pointing to server key file in PEM format"#,
        );
        let cert = env::var("SERVER_CERT_PEMFILE").expect(
            r#"When ENABLE_TLS is set to true the 
        SERVER_CERT_PEMFILE must be set to a filename pointing to server cert file in PEM format"#,
        );
        Some(TlsConfig {
            pem_key_filename: key,
            pem_cert_filename: cert,
        })
    }
}
