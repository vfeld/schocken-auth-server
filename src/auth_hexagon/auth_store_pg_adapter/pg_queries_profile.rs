use std::sync::Arc;

use super::pg_error_mapping::PgUserError;
use log::error;
use sqlx::Row;
use sqlx::{Pool, Postgres};

use super::super::auth_types::*;
use super::{super::auth_store_port::AuthStoreError, pg_error_mapping::filter_user_error};

/// Return the validation time of the day0 token or an error in case it was not valid or not found
pub async fn get_profile(
    pool: Arc<Pool<Postgres>>,
    user_id: &UserId,
) -> Result<UserProfile, AuthStoreError> {
    let res = sqlx::query(
        r#"
SELECT first_name, last_name, email FROM user_profile WHERE user_id = $1;
        "#,
    )
    .bind(&user_id.0)
    .fetch_one(&*pool)
    .await;
    match res {
        Ok(row) => {
            let first_name: String = row.try_get("first_name")?;
            let last_name: String = row.try_get("last_name")?;
            let email: String = row.try_get("email")?;
            Ok(UserProfile {
                first_name,
                last_name,
                email,
            })
        }
        Err(err) => {
            match filter_user_error(&err) {
                Some(PgUserError::DataNotFound) => {
                    let eid = uuid::Uuid::new_v4();
                    let details = "user_id not found in user profile table";
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
