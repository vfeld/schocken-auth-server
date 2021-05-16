use super::super::{auth_service_port::AuthServicePort, auth_types::*};
use actix_web::error::Error;
use actix_web::{cookie, http, http::StatusCode, web, HttpResponse};
use serde_json::json;

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
    let profile = service.get_user_profile(&user_id).await?;
    let (csrf_token, _) = service.create_csrf_token().await?;
    Ok(HttpResponse::Ok()
        .cookie(
            http::Cookie::build("_Host-SCHOCKEN_SESSION", token.0)
                .path("/api/auth")
                .http_only(true)
                .secure(true)
                .same_site(cookie::SameSite::None)
                .expires(expires)
                .finish(),
        )
        .cookie(
            http::Cookie::build(
                "_Host-SCHOCKEN_CSRF",
                format!(
                    "{}_{}_{}",
                    csrf_token,
                    expires.unix_timestamp(),
                    expires.unix_timestamp(),
                ),
            )
            .path("/api/auth")
            .secure(true)
            .expires(expires)
            .same_site(cookie::SameSite::None)
            .finish(),
        )
        .json(json!({
            "first_name": profile.first_name,
            "last_name": profile.last_name,
            "session_expiry": expires.unix_timestamp()
        })))
}

pub async fn auth_session_validate<A>(
    session_token: SessionToken,
    service: web::Data<A>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let (user_id, expiry) = service
        .auth_session_token(&SessionToken(session_token.0))
        .await?;
    let profile = service.get_user_profile(&user_id).await?;

    Ok(HttpResponse::Ok().json(json!({
        "first_name": profile.first_name,
        "last_name": profile.last_name,
        "session_expiry": expiry.unix_timestamp(),
    })))
}

pub async fn auth_session_delete<A>(
    session_token: SessionToken,
    _valid_csrf: ValidateCsrf,
    service: web::Data<A>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let (user_id, _expiry) = service
        .auth_session_token(&SessionToken(session_token.0))
        .await?;
    service.delete_session_token(&user_id).await?;
    let (csrf_token, csrf_expiry) = service.create_csrf_token().await?;

    Ok(HttpResponse::build(StatusCode::OK)
        .cookie(
            http::Cookie::build("_Host-SCHOCKEN_SESSION", "deleted")
                .http_only(true)
                .secure(true)
                .same_site(cookie::SameSite::None)
                .expires(time::OffsetDateTime::from_unix_timestamp(0))
                .finish(),
        )
        .cookie(
            http::Cookie::build(
                "_Host-SCHOCKEN_CSRF",
                format!("{}_{}_{}", csrf_token, csrf_expiry.unix_timestamp(), 0,),
            )
            .path("/api/auth")
            .secure(true)
            .expires(csrf_expiry)
            .same_site(cookie::SameSite::None)
            .finish(),
        )
        .finish())
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
                SessionToken("sessiontoken".to_string()),
                time::OffsetDateTime::now_utc(),
            )));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .post("/api/auth/session")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "_Host-SCHOCKEN_CSRF=csrftoken;")
            .json(&json!({
                "login_name": "John",
                "password":"secret"}))
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::OK);
        let session_cookie = get_cookie(&resp, "_Host-SCHOCKEN_SESSION".to_string()).unwrap();
        assert!(session_cookie.value() == "sessiontoken");
        assert!(session_cookie.http_only());
        assert!(session_cookie.secure());
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
                SessionToken("sessiontoken".to_string()),
                time::OffsetDateTime::now_utc(),
            )));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .post("/api/auth/session")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "_Host-SCHOCKEN_CSRF=csrftoken;")
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
            .will_return(Ok((UserId(uid), time::OffsetDateTime::now_utc())));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api
            .get("/api/auth/session")
            .header(COOKIE, "_Host-SCHOCKEN_SESSION=1234;")
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
            .will_return(Ok((UserId(uid), time::OffsetDateTime::now_utc())));

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
            .header(COOKIE, "_Host-SCHOCKEN_SESSION=1234;")
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
            .header(COOKIE, "_Host-SCHOCKEN_SESSION=1234;")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "_Host-SCHOCKEN_CSRF=csrftoken;")
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
            .header(COOKIE, "_Host-SCHOCKEN_SESSION=1234;")
            .header(COOKIE, "_Host-SCHOCKEN_CSRF=csrftoken;")
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
            .header(COOKIE, "_Host-SCHOCKEN_SESSION=1234;")
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
            .header(COOKIE, "_Host-SCHOCKEN_SESSION=1234;")
            .header("X-Csrf-Token", "csrftoken")
            .header(COOKIE, "_Host-SCHOCKEN_CSRF=csrftoken-1;")
            .send()
            .await
            .unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::FORBIDDEN);
    }
}
