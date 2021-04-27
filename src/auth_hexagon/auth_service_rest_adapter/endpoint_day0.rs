use super::super::{auth_service_port::AuthServicePort, auth_types::*};
use actix_web::error::Error;
use actix_web::{http::StatusCode, web, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterUser {
    pub token: String,
    pub login_name: String,
    pub password: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

pub async fn day0_registration<A>(
    user: web::Json<RegisterUser>,
    service: web::Data<A>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let user = user.into_inner();
    let profile = UserProfile {
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
    };
    let credential = Credential {
        login_name: user.login_name,
        password: user.password,
    };
    let uid = service
        .day0_registration(&profile, &credential, &user.token)
        .await?;
    Ok(HttpResponse::build(StatusCode::OK).json(json!({ "uid": uid })))
}
