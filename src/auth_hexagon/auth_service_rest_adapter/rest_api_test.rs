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

    pub fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.client.delete(self.hosturl.clone() + path)
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

pub fn get_cookie(resp: &reqwest::Response, name: String) -> Option<reqwest::cookie::Cookie> {
    for cookie in resp.cookies() {
        if cookie.name() == name {
            return Some(cookie);
        }
    }
    None
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
