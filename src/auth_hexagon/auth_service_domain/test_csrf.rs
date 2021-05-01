use crate::auth_hexagon::auth_service_port::AuthServicePort;

use super::super::auth_store_mock::AuthStoreMock;
use super::AuthServiceDomain;

#[actix_web::main]
#[test]
async fn test_session_token() {
    let store = AuthStoreMock::new();

    let auth_service = AuthServiceDomain::new(
        store.clone(),
        time::Duration::seconds(10),
        time::Duration::seconds(100),
        "123".into(),
    );
    let csrf1 = auth_service.create_csrf_token().await.unwrap();
    let csrf2 = auth_service.create_csrf_token().await.unwrap();
    assert!(csrf1 != csrf2);
}
