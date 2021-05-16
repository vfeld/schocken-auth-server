use auth_hexagon::{auth_config_port::AuthConfigPort, auth_service_port::AuthServicePort};
use log::info;

mod auth_hexagon;

use crate::auth_hexagon::auth_config_env_adapter::AuthConfigEnvAdapter;
use crate::auth_hexagon::auth_service_domain::AuthServiceDomain;
use crate::auth_hexagon::auth_service_rest_adapter::AuthServiceRestAdapter;
use crate::auth_hexagon::auth_store_pg_adapter::AuthStorePgAdapter;

#[actix_web::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //use dotenv;
    dotenv::dotenv().ok();
    env_logger::init();

    let auth_config_env = AuthConfigEnvAdapter::new();

    //setup the db backend
    let db_user = auth_config_env.db_user().await;
    let db_pwd = auth_config_env.db_pwd().await;
    let db_host = auth_config_env.db_host().await;
    let db_port = auth_config_env.db_port().await;
    let db_name = auth_config_env.db_name().await;

    let auth_store_pg =
        AuthStorePgAdapter::new(&db_user, &db_pwd, &db_host, &db_port.to_string(), &db_name).await;

    let day0_token_lifetime = auth_config_env.day0_token_lifetime().await;
    let session_lifetime = auth_config_env.session_lifetime().await;
    let jwt_signing_secret = auth_config_env.jwt_signing_secret().await;

    //setup the authentication service
    let auth_service = AuthServiceDomain::new(
        auth_store_pg.clone(),
        day0_token_lifetime,
        session_lifetime,
        jwt_signing_secret,
    );

    //set the day0 token/password for intial registration
    let day0_token = auth_config_env.day0_token().await;
    auth_service.set_day0_token(&day0_token).await?;

    //setup the http server
    let host = auth_config_env.host().await;
    let port = auth_config_env.port().await;
    let allowed_origin = auth_config_env.allowed_origin().await;
    let tls_config = auth_config_env.tls_server_config().await;

    let server = AuthServiceRestAdapter::new(
        &host,
        &port.to_string(),
        auth_service,
        allowed_origin,
        tls_config,
    )
    .run()
    .await;
    info!("http server has started");

    server.await?;

    Ok(())
}
