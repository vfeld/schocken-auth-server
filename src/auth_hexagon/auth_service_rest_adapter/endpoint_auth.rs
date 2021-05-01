use super::super::{auth_service_port::AuthServicePort, auth_types::*};
use actix_web::error::Error;
use actix_web::{cookie, http, http::StatusCode, web, HttpResponse};

pub async fn auth_session_create<A>(
    credential: web::Json<Credential>,
    _valid_csrf: ValidateCsrf,
    service: web::Data<A>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let credential = credential.into_inner();
    let user_id = service.auth_credential(&credential).await?;
    let (token, expires) = service.create_session_token(&user_id).await?;
    Ok(HttpResponse::Ok()
        .cookie(
            http::Cookie::build("SCHOCKEN_SESSION", token)
                .http_only(true)
                .secure(true)
                .same_site(cookie::SameSite::Strict)
                .expires(expires)
                .finish(),
        )
        .finish())
}

pub async fn auth_session_validate<A>(
    _user_id: UserId,
    _service: web::Data<A>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    //validation is performed by the authorizing UserId (in the FromRequest trait impl)
    Ok(HttpResponse::Ok().finish())
}

pub async fn auth_session_delete<A>(
    user_id: UserId,
    _valid_csrf: ValidateCsrf,
    service: web::Data<A>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    service.delete_session_token(&user_id).await?;
    Ok(HttpResponse::build(StatusCode::OK).finish())
}

#[cfg(test)]
mod test {
    use crate::auth_hexagon::auth_service_mock::AuthServiceMock;
    use crate::auth_hexagon::auth_service_port::AuthServiceError;
    use crate::auth_hexagon::auth_service_rest_adapter::rest_api_test::{
        get_cookie, init, ApiTestDriver,
    };
    use crate::auth_hexagon::auth_types::*;
    use mock_it::Matcher::*;
    use reqwest::{header::COOKIE, StatusCode};
    use serde_json::json;

    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_create_success() {
        //test configuration
        init();
        let uid = 3i64;

        let auth_service = AuthServiceMock::new();
        auth_service
            .auth_credential
            .given(Any)
            .will_return(Ok(UserId(uid)));

        auth_service
            .create_session_token
            .given(Any)
            .will_return(Ok((
                "sessiontoken".to_string(),
                time::OffsetDateTime::now_utc(),
            )));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .post("/api/auth/session")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "SCHOCKEN_CSRF=csrftoken;")
            .json(&json!({
                "login_name": "John",
                "password":"secret"}))
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::OK);
        let session_cookie = get_cookie(&resp, "SCHOCKEN_SESSION".to_string()).unwrap();
        assert!(session_cookie.value() == "sessiontoken");
        assert!(session_cookie.http_only());
        assert!(session_cookie.secure());
        assert!(session_cookie.same_site_strict());
        assert!(session_cookie.expires() != None);
    }
    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_create_unauthorized() {
        //test configuration
        init();

        let auth_service = AuthServiceMock::new();
        auth_service
            .auth_credential
            .given(Any)
            .will_return(Err(AuthServiceError::Unauthorized(
                "1".to_string(),
                "test login".to_string(),
            )));

        auth_service
            .create_session_token
            .given(Any)
            .will_return(Ok((
                "sessiontoken".to_string(),
                time::OffsetDateTime::now_utc(),
            )));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .post("/api/auth/session")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "SCHOCKEN_CSRF=csrftoken;")
            .json(&json!({
                "login_name": "John",
                "password":"secret"}))
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::UNAUTHORIZED);
    }

    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_validate_success() {
        //test configuration
        init();
        let uid = 3i64;

        let auth_service = AuthServiceMock::new();
        auth_service
            .auth_session_token
            .given(Any)
            .will_return(Ok(UserId(uid)));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .get("/api/auth/session")
            .header(COOKIE, "SCHOCKEN_SESSION=1234;")
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::OK);
    }

    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_no_cookie() {
        //test configuration
        init();
        let uid = 3i64;

        let auth_service = AuthServiceMock::new();
        auth_service
            .auth_session_token
            .given(Any)
            .will_return(Ok(UserId(uid)));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api.get("/api/auth/session").send().await.unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::UNAUTHORIZED);
    }

    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_wrong_cookie() {
        //test configuration
        init();

        let auth_service = AuthServiceMock::new();
        auth_service.auth_session_token.given(Any).will_return(Err(
            AuthServiceError::Unauthorized("1".to_string(), "test error".to_string()),
        ));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .get("/api/auth/session")
            .header(COOKIE, "SCHOCKEN_SESSION=1234;")
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::UNAUTHORIZED);
    }
    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_delete_success() {
        //test configuration
        init();

        let auth_service = AuthServiceMock::new();
        auth_service
            .delete_session_token
            .given(Any)
            .will_return(Ok(()));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .delete("/api/auth/session")
            .header(COOKIE, "SCHOCKEN_SESSION=1234;")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "SCHOCKEN_CSRF=csrftoken;")
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::OK);
    }
    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_delete_no_csrf_header() {
        //test configuration
        init();

        let auth_service = AuthServiceMock::new();
        auth_service
            .delete_session_token
            .given(Any)
            .will_return(Ok(()));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .delete("/api/auth/session")
            .header(COOKIE, "SCHOCKEN_SESSION=1234;")
            .header(COOKIE, "SCHOCKEN_CSRF=csrftoken;")
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::FORBIDDEN);
    }
    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_delete_no_csrf_cookie() {
        //test configuration
        init();

        let auth_service = AuthServiceMock::new();
        auth_service
            .delete_session_token
            .given(Any)
            .will_return(Ok(()));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .delete("/api/auth/session")
            .header(COOKIE, "SCHOCKEN_SESSION=1234;")
            .header("X-Csrf-Token", "csrftoken")
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::FORBIDDEN);
    }
    #[actix_web::main]
    #[test]
    pub async fn test_auth_session_delete_csrf_invalid() {
        //test configuration
        init();

        let auth_service = AuthServiceMock::new();
        auth_service
            .delete_session_token
            .given(Any)
            .will_return(Ok(()));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .delete("/api/auth/session")
            .header(COOKIE, "SCHOCKEN_SESSION=1234;")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "SCHOCKEN_CSRF=csrftoken-1;")
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::FORBIDDEN);
    }
}