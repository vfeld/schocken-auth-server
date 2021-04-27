use mock_it::Matcher;

use crate::auth_hexagon::auth_service_port::AuthServicePort;

use super::super::auth_store_mock::AuthStoreMock;
use super::AuthServiceDomain;

#[actix_web::main]
#[test]
async fn test_session_token() {
    let store = AuthStoreMock::new();
    store
        .get_user_id_by_session_id
        .given(Matcher::Any)
        .will_return(Ok(Some(7i64)));

    let auth_service_123_100 = AuthServiceDomain::new(
        store.clone(),
        time::Duration::seconds(10),
        time::Duration::seconds(100),
        "123".into(),
    );

    let token_123_100 = match auth_service_123_100.create_session_token(&7).await {
        Ok(token) => token,
        Err(_) => {
            assert!(false);
            "".into()
        }
    };

    let auth_service_123_0 = AuthServiceDomain::new(
        store.clone(),
        time::Duration::seconds(10),
        time::Duration::seconds(-1),
        "123".into(),
    );

    let token_123_0 = match auth_service_123_0.create_session_token(&7).await {
        Ok(token) => token,
        Err(_) => {
            assert!(false);
            "".into()
        }
    };

    let auth_service_456_100 = AuthServiceDomain::new(
        store.clone(),
        time::Duration::seconds(10),
        time::Duration::seconds(100),
        "456".into(),
    );

    let token_456_100 = match auth_service_456_100.create_session_token(&7).await {
        Ok(token) => token,
        Err(_) => {
            assert!(false);
            "".into()
        }
    };

    //success
    match auth_service_123_100
        .auth_session_token(&token_123_100)
        .await
    {
        Ok(_) => {
            assert!(true)
        }
        Err(_) => {
            assert!(false)
        }
    }
    // wrong signature
    match auth_service_123_100
        .auth_session_token(&token_456_100)
        .await
    {
        Ok(_) => {
            assert!(false)
        }
        Err(_) => {
            assert!(true)
        }
    }
    // expired
    match auth_service_123_100.auth_session_token(&token_123_0).await {
        Ok(_) => {
            assert!(false)
        }
        Err(_) => {
            assert!(true)
        }
    }
    // wrong user
    let store = AuthStoreMock::new();
    store
        .get_user_id_by_session_id
        .given(Matcher::Any)
        .will_return(Ok(None));

    let auth_service_123_100 = AuthServiceDomain::new(
        store.clone(),
        time::Duration::seconds(10),
        time::Duration::seconds(100),
        "123".into(),
    );

    let token_123_100 = match auth_service_123_100.create_session_token(&7).await {
        Ok(token) => token,
        Err(_) => {
            assert!(false);
            "".into()
        }
    };
    store
        .get_user_id_by_session_id
        .given(Matcher::Any)
        .will_return(Ok(None));
    match auth_service_123_100
        .auth_session_token(&token_123_100)
        .await
    {
        Ok(_) => {
            assert!(false)
        }
        Err(_) => {
            assert!(true)
        }
    }
    //delete token
    match auth_service_123_100.delete_session_token(&7).await {
        Ok(_) => {
            assert!(true)
        }
        Err(_) => {
            assert!(false)
        }
    }
}
