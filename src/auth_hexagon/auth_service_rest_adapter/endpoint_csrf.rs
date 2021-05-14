use crate::auth_hexagon::auth_types::AllowedOrigin;

use super::super::auth_service_port::AuthServicePort;
use actix_web::{cookie, error::Error, http, web, HttpResponse};

pub async fn csrf_page<A>(
    service: web::Data<A>,
    allowed_origin: web::Data<AllowedOrigin>,
) -> Result<HttpResponse, Error>
where
    A: AuthServicePort,
{
    let (token, expires) = service.create_csrf_token().await?;
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
        function listenCookieChange(interval = 100) {{
            let lastToken = getCookie("_Host-SCHOCKEN_CSRF");
            let id = setInterval(()=> {{
                const token = getCookie("_Host-SCHOCKEN_CSRF");
                if (token !== lastToken) {{
                    try {{
                        const expiry = getCookie("_Host-SCHOCKEN_CSRF_EXPIRY");
                        window.parent.postMessage(token, target_origin);                        
                        clearInterval(id);
                    }} finally {{
                        lastToken = token;
                    }}
                }}
            }}, interval);
        }}
        window.addEventListener("message", (event) => {{
            if (event.origin !== target_origin)
                return;
            if (event.data !== 'GET_CSRF_TOKEN')
                return;
            const token = getCookie("_Host-SCHOCKEN_CSRF");
            window.parent.postMessage(token, target_origin);
        }}, false);
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
                format!("{}_{}", token, expires.unix_timestamp()),
            )
            .path("/api/auth")
            .secure(true)
            .expires(expires)
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
        assert!(session_cookie.value() == "csrftoken");
        assert!(!session_cookie.http_only());
        assert!(session_cookie.secure());
    }
}
