use crate::auth_hexagon::auth_types::SessionToken;

use super::{
    auth_service_port::{AuthServiceError, AuthServicePort},
    auth_types::AllowedOrigin,
    auth_types::ValidateCsrf,
};
use actix_cors::Cors;
use actix_web::{
    dev::Payload, dev::Server, http, web::Data, App, FromRequest, HttpMessage, HttpRequest,
    HttpServer,
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

pub fn configure_service_endpoints<A>(
    config: &mut web::ServiceConfig,
    service: A,
    allowed_origin: String,
) where
    A: AuthServicePort + Send + Sync + 'static,
{
    let origin = AllowedOrigin {
        origin: allowed_origin,
    };
    config.service(web::scope("/api/auth").configure(|config| {
        config.data(service);
        config.data(origin);
        config.route(
            "/register/day0/{token}",
            web::put().to(endpoint_day0::day0_registration::<A>),
        );
        config.route(
            "/session",
            web::post().to(endpoint_auth::auth_session_create::<A>),
        );
        config.route(
            "/session",
            web::get().to(endpoint_auth::auth_session_validate::<A>),
        );
        config.route(
            "/session",
            web::delete().to(endpoint_auth::auth_session_delete::<A>),
        );
        config.route("/csrf", web::get().to(endpoint_csrf::csrf_page::<A>));
    }));
}

pub fn logger_middleware() -> Logger {
    Logger::default()
}

pub fn cors_middleware(allowed_origin: String) -> Cors {
    Cors::default()
        .allowed_origin(&allowed_origin)
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .supports_credentials()
        .allowed_header(http::header::CONTENT_TYPE)
        .allowed_header(http::HeaderName::from_static("x-csrf-token"))
        .max_age(60)
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
    allowed_origin: String,
}

impl<A> AuthServiceRestAdapter<A>
where
    A: AuthServicePort + Send + Sync + Clone + 'static,
{
    pub fn new(host: &str, port: &str, service: A, allowed_origin: String) -> Self {
        AuthServiceRestAdapter {
            host: host.into(),
            port: port.into(),
            service,
            allowed_origin,
        }
    }

    pub async fn run(&self) -> Server {
        let service = self.service.clone(); //decouple lifetime of service from self
        let address = format!("{}:{}", self.host, self.port);
        let allowed_origin = self.allowed_origin.clone();
        HttpServer::new(move || {
            App::new()
                .app_data(json_config())
                .app_data::<Data<Box<dyn AuthServicePort>>>(Data::new(Box::new(service.clone())))
                .wrap(cors_middleware(allowed_origin.clone()))
                .wrap(logger_middleware())
                .configure(|config| {
                    configure_service_endpoints(config, service.clone(), allowed_origin.clone())
                })
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

        let csrf_cookie = match req.cookie("_Host-SCHOCKEN_CSRF") {
            Some(token) => token,
            None => {
                let uuid = uuid::Uuid::new_v4();
                let details = "_Host-SCHOCKEN_CSRF cookie missing";
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
impl FromRequest for SessionToken {
    type Config = ();
    type Error = AuthServiceError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        if let Some(cookie) = req.cookie("_Host-SCHOCKEN_SESSION") {
            let session = cookie.value().to_owned();
            return ok(SessionToken(session));
        }
        let uuid = uuid::Uuid::new_v4();
        let details = "session token can not extracted from http request";
        error!("eid: {}, details: {}", uuid, details);
        err(AuthServiceError::Unauthorized(
            uuid.to_string(),
            details.to_string(),
        ))
    }
}
