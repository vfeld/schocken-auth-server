use super::super::{auth_service_port::AuthServicePort, auth_types::*};
use actix_web::error::Error;
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterUser {
    pub login_name: String,
    pub password: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

pub async fn day0_registration<A>(
    token: web::Path<(String,)>,
    user: web::Json<RegisterUser>,
    service: web::Data<A>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let token = token.into_inner().0;
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
    service
        .day0_registration(&profile, &credential, &token)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

#[cfg(test)]
mod test {
    use crate::auth_hexagon::auth_service_mock::AuthServiceMock;
    use crate::auth_hexagon::auth_service_rest_adapter::rest_api_test::{init, ApiTestDriver};
    use mock_it::verify;

    use crate::auth_hexagon::auth_types::*;
    use mock_it::Matcher::*;
    use reqwest::StatusCode;
    use serde::Deserialize;
    use serde_json::json;

    #[actix_web::main]
    #[test]
    pub async fn test_register_day0() {
        //test configuration
        init();
        let token = "1234567890";
        let profile = UserProfile {
            first_name: "John".into(),
            last_name: "Doe".into(),
            email: "john.doe@example.local".into(),
        };
        let cred = Credential {
            login_name: "john.doe+login@example.local".into(),
            password: "secret".into(),
        };
        let uid = 3i64;

        let auth_service = AuthServiceMock::new();
        auth_service
            .day0_registration
            .given(Any)
            .will_return(Ok(UserId(uid)));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .put(&format!("/api/register/day0/{}", token))
            .json(&json!({
            "login_name":cred.login_name,
            "password":cred.password,
            "email":profile.email,
            "first_name":profile.first_name,
            "last_name":profile.last_name}))
            .send()
            .await
            .unwrap();

        assert!(resp.status() == StatusCode::OK);
        let d = Val((profile, cred, token.to_string()));
        assert!(verify(
            auth_service.day0_registration.was_called_with(d).times(1)
        ));
    }
    #[actix_web::main]
    #[test]
    pub async fn test_register_day0_corrupted_request() {
        //test configuration
        init();
        let token = "1234567890";
        let profile = UserProfile {
            first_name: "John".into(),
            last_name: "Doe".into(),
            email: "john.doe@example.local".into(),
        };
        let cred = Credential {
            login_name: "john.doe+login@example.local".into(),
            password: "secret".into(),
        };

        let auth_service = AuthServiceMock::new();

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .put(&format!("/api/register/day0/{}", token))
            .json(&json!({
            "password":cred.password,
            "email":profile.email,
            "first_name":profile.first_name,
            "last_name":profile.last_name}))
            .send()
            .await
            .unwrap();

        //test verdict
        #[derive(Deserialize)]
        struct TestResponse {
            reason: String,
        }
        assert!(resp.status() == StatusCode::CONFLICT);
        assert!(resp.json::<TestResponse>().await.unwrap().reason == "JsonPayloadError");
    }
}
