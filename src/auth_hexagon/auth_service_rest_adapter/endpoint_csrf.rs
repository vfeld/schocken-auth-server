use crate::auth_hexagon::auth_types::{AllowedOrigin, SessionToken};

use super::super::auth_service_port::AuthServicePort;
use actix_web::{
    cookie,
    error::Error,
    http,
    web::{self},
    HttpMessage, HttpRequest, HttpResponse,
};

pub async fn csrf_page<A>(
    req: HttpRequest,
    service: web::Data<A>,
    allowed_origin: web::Data<AllowedOrigin>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let session_expiry_unix = if let Some(cookie) = req.cookie("_Host-SCHOCKEN_SESSION") {
        let session_token = SessionToken(cookie.value().to_owned());
        match service.auth_session_token(&session_token).await {
            Ok((_user_id, session_expiry)) => session_expiry.unix_timestamp(),
            _ => 0,
        }
    } else {
        0
    };
    let (token, token_expiry) = service.create_csrf_token().await?;
    let body = format!(
        r#"
<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="data:;base64,iVBORw0KGgo=">
    <title>CSRF Token Provider</title>
    <script>
        const target_origin = '{}';

        function getCookie(name) {{
            if (!document.cookie) {{
                return null;
            }}
        
            const xsrfCookies = document.cookie.split(';')
                .map(c => c.trim())
                .filter(c => c.startsWith(name + '='));
        
            if (xsrfCookies.length === 0) {{
                return null;
            }}
            return decodeURIComponent(xsrfCookies[0].split(/=(.+)/)[1]);
        }}

        function listenCookieChange(interval = 500) {{
            let lastToken = '';
            let id = setInterval(()=> {{
                const token = getCookie("_Host-SCHOCKEN_CSRF");
                if (token === null) return;
                if (token === '') return;
                if (token !== lastToken) {{
                    try {{
                        window.parent.postMessage(token, target_origin);                        
                        lastToken = token;
                        //console.log("INFO: Csrf Fetcher iframe, did deliver token to parent");
                    }} catch (e) {{
                        //console.log("INFO: Csrf Fetcher iframe, did not deliver token to parent");
                    }}
                }}
            }}, interval);
        }}

        listenCookieChange();
    </script>
</head>
</html>
"#,
        allowed_origin.origin
    );
    Ok(HttpResponse::Ok()
        .cookie(
            http::Cookie::build(
                "_Host-SCHOCKEN_CSRF",
                format!(
                    "{}_{}_{}",
                    token,
                    token_expiry.unix_timestamp(),
                    session_expiry_unix
                ),
            )
            .path("/api/auth")
            .secure(true)
            .expires(token_expiry)
            .same_site(cookie::SameSite::None)
            .finish(),
        )
        .content_type("text/html; charset=utf-8")
        .append_header(http::header::CacheControl(vec![
            http::header::CacheDirective::NoCache,
        ]))
        .body(body))
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
        auth_service.create_csrf_token.given(Any).will_return(Ok((
            "csrftoken".to_string(),
            time::OffsetDateTime::now_utc(),
        )));
        let api = ApiTestDriver::new(auth_service.clone()).await;

        //test execution
        let resp = api.get("/api/auth/csrf").send().await.unwrap();

        //test verdict
        assert!(resp.status() == StatusCode::OK);
        let session_cookie = get_cookie(&resp, "_Host-SCHOCKEN_CSRF".to_string()).unwrap();
        assert!(session_cookie.value().split("_").into_iter().count() == 3);
        assert!(
            session_cookie
                .value()
                .split("_")
                .into_iter()
                .next()
                .unwrap()
                == "csrftoken"
        );
        assert!(!session_cookie.http_only());
        assert!(session_cookie.secure());
    }
}
