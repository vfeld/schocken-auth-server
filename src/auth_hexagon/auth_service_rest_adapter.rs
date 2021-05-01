use std::pin::Pin;

use super::{
    auth_service_port::{AuthServiceError, AuthServicePort},
    auth_types::UserId,
    auth_types::ValidateCsrf,
};
use actix_web::{
    dev::Payload, dev::Server, web::Data, App, FromRequest, HttpMessage, HttpRequest, HttpServer,
};
use actix_web::{http::StatusCode, middleware::Logger, web, HttpResponse, ResponseError};
use futures_util::future::{err, ok, Ready};
use log::error;
use serde_json::json;

pub mod endpoint_auth;
pub mod endpoint_csrf;
pub mod endpoint_day0;

#[cfg(test)]
pub mod rest_api_test;

pub fn configure_service_endpoints<A>(config: &mut web::ServiceConfig, service: A)
where
    A: AuthServicePort + Send + Sync + 'static,
{
    config.service(web::scope("/api").configure(|config| {
        config.data(service);
        config.route(
            "/token/day0",
            web::post().to(endpoint_day0::day0_registration::<A>),
        );
        config.route(
            "/auth/session",
            web::post().to(endpoint_auth::auth_session_create::<A>),
        );
        config.route(
            "/auth/session",
            web::get().to(endpoint_auth::auth_session_validate::<A>),
        );
        config.route(
            "/auth/session",
            web::delete().to(endpoint_auth::auth_session_delete::<A>),
        );
        config.route("/csrf", web::get().to(endpoint_csrf::csrf_create::<A>));
    }));
}

pub fn logger_middleware() -> Logger {
    Logger::default()
}

pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(4096)
        .error_handler(|err, _req| {
            let uuid = uuid::Uuid::new_v4();
            let details = format!("JSON payload error, {}", err.to_string());
            error!("eid: {}, details: {}", uuid, details);
            actix_web::error::InternalError::from_response(
                "JSON payload error",
                HttpResponse::Conflict()
                    .json(json!({ "reason": "JsonPayloadError", "eid": uuid.to_string()})),
            )
            .into()
        })
}

pub struct AuthServiceRestAdapter<A>
where
    A: AuthServicePort + Send + Sync + Clone + 'static,
{
    host: String,
    port: String,
    service: A,
}

impl<A> AuthServiceRestAdapter<A>
where
    A: AuthServicePort + Send + Sync + Clone + 'static,
{
    pub fn new(host: &str, port: &str, service: A) -> Self {
        AuthServiceRestAdapter {
            host: host.into(),
            port: port.into(),
            service,
        }
    }

    pub async fn run(&self) -> Server {
        let service = self.service.clone(); //decouple lifetime of service from self
        let address = format!("{}:{}", self.host, self.port);
        HttpServer::new(move || {
            App::new()
                .app_data(json_config())
                .app_data::<Data<Box<dyn AuthServicePort>>>(Data::new(Box::new(service.clone())))
                .wrap(logger_middleware())
                .configure(|config| configure_service_endpoints(config, service.clone()))
        })
        .bind(address)
        .expect("Unable to bind server")
        .workers(1)
        .run()
    }
}

impl ResponseError for AuthServiceError {
    fn error_response(&self) -> HttpResponse {
        let eid = self.eid();
        let (status_code, reason) = match self {
            AuthServiceError::RegistrationNotAllowed(_, _) => {
                (StatusCode::CONFLICT, "RegistrationNotAllowed")
            }
            AuthServiceError::ConnectivityProblem(_, _) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "ConnectivityProblem")
            }
            AuthServiceError::UserAlreadyExists(_, _) => {
                (StatusCode::CONFLICT, "UserAlreadyExists")
            }
            AuthServiceError::InvalidOneTimeToken(_, _) => {
                (StatusCode::UNAUTHORIZED, "InvalidOneTimeToken")
            }
            AuthServiceError::Unauthorized(_, _) => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthServiceError::InternalError(_, _) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "InternalError")
            }
            AuthServiceError::InvalidCsrfToken(_, _) => (StatusCode::FORBIDDEN, "InvalidCsrfToken"),
        };
        HttpResponse::build(status_code).json(json!({ "reason": reason, "eid": eid}))
    }
}

impl FromRequest for UserId {
    type Config = ();
    type Error = AuthServiceError;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<UserId, AuthServiceError>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let data = req
            .app_data::<Data<Box<dyn AuthServicePort>>>()
            .unwrap()
            .to_owned();
        if let Some(session) = req.cookie("SCHOCKEN_SESSION") {
            let u = Box::pin(async move { data.auth_session_token(&session.to_string()).await });
            return u;
        }
        let uuid = uuid::Uuid::new_v4();
        let details = "session is not unauthorized";
        error!("eid: {}, details: {}", uuid, details);
        let e = Box::pin(async move {
            Err(AuthServiceError::Unauthorized(
                uuid.to_string(),
                details.to_string(),
            ))
        });
        e
    }
}

impl FromRequest for ValidateCsrf {
    type Config = ();
    type Error = AuthServiceError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let csrf_header = match req.headers().get("X-Csrf-Token") {
            Some(token) => token,
            None => {
                let uuid = uuid::Uuid::new_v4();
                let details = "X-Csrf-Token header missing";
                error!("eid: {}, details: {}", uuid, details);
                return err(AuthServiceError::InvalidCsrfToken(
                    uuid.to_string(),
                    details.to_string(),
                ));
            }
        };

        let csrf_header_value = match csrf_header.to_str() {
            Ok(token) => token,
            Err(e) => {
                let uuid = uuid::Uuid::new_v4();
                let details = format!("X-Csrf-Token header value malformed: {}", e.to_string());
                error!("eid: {}, details: {}", uuid, details);
                return err(AuthServiceError::InvalidCsrfToken(
                    uuid.to_string(),
                    details.to_string(),
                ));
            }
        };

        let csrf_cookie = match req.cookie("SCHOCKEN_CSRF") {
            Some(token) => token,
            None => {
                let uuid = uuid::Uuid::new_v4();
                let details = "SCHOCKEN_CSRF cookie missing";
                error!("eid: {}, details: {}", uuid, details);
                return err(AuthServiceError::InvalidCsrfToken(
                    uuid.to_string(),
                    details.to_string(),
                ));
            }
        };

        let csrf_cookie_value = csrf_cookie.value();
        if csrf_cookie_value != csrf_header_value {
            let uuid = uuid::Uuid::new_v4();
            let details = "CSRF header/cookie mismatch";
            error!("eid: {}, details: {}", uuid, details);
            return err(AuthServiceError::InvalidCsrfToken(
                uuid.to_string(),
                details.to_string(),
            ));
        }
        ok(ValidateCsrf {})
    }
}
