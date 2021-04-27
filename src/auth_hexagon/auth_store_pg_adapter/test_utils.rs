use super::super::auth_store_pg_adapter::*;
use uuid::Uuid;

pub async fn pg_store_init(test_name: &str) -> Box<dyn AuthStorePort> {
    dotenv::dotenv().ok();

    let _ = env_logger::builder().is_test(true).try_init();
    let db_user = std::env::var("DB_USER").unwrap_or("pgadmin".into());
    let db_pwd = std::env::var("DB_PWD").unwrap_or("secret".into());
    let db_host = std::env::var("DB_HOST").unwrap_or("localhost".into());
    let db_port = std::env::var("DB_PORT").unwrap_or("5432".into());
    let db_name = std::env::var("DB_NAME").unwrap_or("schocken".into());
    let test_exe_id = Uuid::new_v4().to_string().replace("-", "");

    let test_db_name = format!("{}_{}", test_name, test_exe_id);
    let name = if test_db_name.len() > 63 {
        &test_db_name[..63]
    } else {
        &test_db_name[..]
    };
    println!("DB Name: {}", name);
    AuthStorePgAdapter::create_db(&db_user, &db_pwd, &db_host, &db_port, &db_name, &name)
        .await
        .unwrap();
    let store = AuthStorePgAdapter::new(&db_user, &db_pwd, &db_host, &db_port, &name).await;
    Box::new(store)
}
