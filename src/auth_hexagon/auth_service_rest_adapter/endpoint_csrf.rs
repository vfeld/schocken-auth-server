use super::super::auth_service_port::AuthServicePort;
use actix_web::error::Error;
use actix_web::{http, web, HttpResponse};

pub async fn csrf_create<A>(service: web::Data<A>) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let token = service.create_csrf_token().await?;
    Ok(HttpResponse::Ok()
        .cookie(
            http::Cookie::build("SCHOCKEN_CSRF", token)
                .secure(true)
                .finish(),
        )
        .finish())
}

#[cfg(test)]
mod test {
    use crate::auth_hexagon::auth_service_mock::AuthServiceMock;
    use crate::auth_hexagon::auth_service_rest_adapter::rest_api_test::{
        get_cookie, init, ApiTestDriver,
    };
    use mock_it::Matcher::*;
    use reqwest::StatusCode;

    #[actix_web::main]
    #[test]
    pub async fn test_create_csrf() {
        //test configuration
        init();

        let auth_service = AuthServiceMock::new();
        auth_service
            .create_csrf_token
            .given(Any)
            .will_return(Ok("csrftoken".to_string()));

        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api.get("/api/csrf").send().await.unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::OK);
        let session_cookie = get_cookie(&resp, "SCHOCKEN_CSRF".to_string()).unwrap();
        assert!(session_cookie.value() == "csrftoken");
        assert!(!session_cookie.http_only());
        assert!(session_cookie.secure());
    }
}
