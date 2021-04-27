use super::auth_service_port::{AuthServiceError, AuthServicePort};
use actix_web::{dev::Server, App, HttpServer};
use actix_web::{http::StatusCode, middleware::Logger, web, HttpResponse, ResponseError};
use log::error;
use serde_json::json;

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
        };
        HttpResponse::build(status_code).json(json!({ "reason": reason, "eid": eid}))
    }
}
