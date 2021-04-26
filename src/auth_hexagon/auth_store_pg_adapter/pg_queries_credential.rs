use std::sync::Arc;

use super::pg_error_mapping::PgUserError;
use log::error;
use sqlx::Row;
use sqlx::{Pool, Postgres};

use super::super::auth_types::*;
use super::{super::auth_store_port::AuthStoreError, pg_error_mapping::filter_user_error};

/// Return the validation time of the day0 token or an error in case it was not valid or not found
pub async fn get_pwd_hash(
    pool: Arc<Pool<Postgres>>,
    login_name: &str,
) -> Result<(UserId, Vec<u8>), AuthStoreError> {
    let res = sqlx::query(
        r#"
SELECT user_id, pwd_hash FROM credentials WHERE login_name = $1;
        "#,
    )
    .bind(&login_name)
    .fetch_one(&*pool)
    .await;
    match res {
        Ok(row) => {
            let user_id: UserId = row.try_get("user_id")?;
            let pwd_hash: Vec<u8> = row.try_get("pwd_hash")?;
            Ok((user_id, pwd_hash))
        }
        Err(err) => {
            match filter_user_error(&err) {
                Some(PgUserError::DataNotFound) => {
                    let eid = uuid::Uuid::new_v4();
                    let details = "credential not found";
                    error!("eid: {}, details: {}", eid, details);
                    return Err(AuthStoreError::DataNotFound(
                        eid.to_string(),
                        details.into(),
                    ));
                }
                _ => {}
            }
            let e: AuthStoreError = err.into();
            let eid = e.eid();
            error!("eid: {}, error when fetching credentials", eid);
            return Err(e);
        }
    }
}
