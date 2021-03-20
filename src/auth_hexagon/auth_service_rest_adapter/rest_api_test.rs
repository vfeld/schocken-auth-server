use mock_it::verify;
use mock_it::Matcher::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

use super::super::auth_config_env_adapter::AuthConfigEnvAdapter;
use super::super::auth_config_port::*;
use super::super::auth_service_mock::AuthServiceMock;
use super::*;

#[derive(Debug, Clone)]
pub struct Counter {
    _count: Arc<Mutex<u16>>,
}

impl Counter {
    pub fn new(init: u16) -> Self {
        Self {
            _count: Arc::new(Mutex::new(init)),
        }
    }

    pub fn next(&self) -> u16 {
        let mut c = self._count.lock().unwrap();
        let this_c = *c;
        *c += 1;
        this_c
    }
}

pub struct ApiTestDriver {
    hosturl: String,
    _server: Server,
    client: reqwest::Client,
}

impl ApiTestDriver {
    pub async fn new<T>(service: T) -> Self
    where
        T: AuthServicePort + Send + Sync + Clone + 'static,
    {
        let auth_config_env = AuthConfigEnvAdapter::new();
        let host = auth_config_env.host().await;
        let port = auth_config_env.port().await + COUNTER.next();

        let hosturl = format!("http://{}:{}", host, port);

        let server = AuthServiceRestAdapter::new(&host, &port.to_string(), service)
            .run()
            .await;

        let client = reqwest::Client::builder()
            //.http2_prior_knowledge()
            .build()
            .unwrap();

        ApiTestDriver {
            hosturl,
            _server: server,
            client,
        }
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.client.post(self.hosturl.clone() + path)
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client.get(self.hosturl.clone() + path)
    }
}

pub fn init() {
    dotenv::dotenv().ok();
    lazy_static::initialize(&COUNTER)
}

use lazy_static::lazy_static;
lazy_static! {
    pub static ref COUNTER: Counter = Counter::new(0);
}

#[actix_web::main]
#[test]
pub async fn test_not_found() {
    //test configuration
    init();

    let auth_service = AuthServiceMock::new();

    let api = ApiTestDriver::new(auth_service.clone()).await;

    //test execution
    let resp = api.get("/api/doesnotexist").send().await.unwrap();

    assert!(resp.status() == StatusCode::NOT_FOUND);
}

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
        .will_return(Ok(uid));

    let api = ApiTestDriver::new(auth_service.clone()).await;

    //test execution
    let resp = api
        .post("/api/token/day0")
        .json(&json!({
            "token": token,
            "login_name":cred.login_name,
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
        uid: i64,
    }
    assert!(resp.status() == StatusCode::OK);
    assert!(resp.json::<TestResponse>().await.unwrap().uid == uid);
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
        .post("/api/token/day0")
        .json(&json!({
            "token": token,
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
