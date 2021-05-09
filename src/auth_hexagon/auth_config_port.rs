#[async_trait::async_trait]
pub trait AuthConfigPort {
    async fn day0_token_lifetime(&self) -> time::Duration;
    async fn day0_token(&self) -> String;
    async fn db_host(&self) -> String;
    async fn db_port(&self) -> u16;
    async fn db_user(&self) -> String;
    async fn db_pwd(&self) -> String;
    async fn db_name(&self) -> String;
    async fn host(&self) -> String;
    async fn port(&self) -> u16;
    async fn session_lifetime(&self) -> time::Duration;
    async fn jwt_signing_secret(&self) -> String;
    async fn allowed_origin(&self) -> String;
}
