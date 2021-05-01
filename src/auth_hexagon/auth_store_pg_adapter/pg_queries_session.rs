use std::sync::Arc;

use super::pg_error_mapping::PgUserError;
use log::error;
use sqlx::Row;
use sqlx::{Pool, Postgres};

use super::super::auth_types::*;
use super::{super::auth_store_port::AuthStoreError, pg_error_mapping::filter_user_error};

/// Insert a new session id
pub async fn insert_session_id(
    pool: Arc<Pool<Postgres>>,
    user_id: &UserId,
    session_id: &str,
) -> Result<(), AuthStoreError> {
    let rec = sqlx::query(
        r#"
INSERT INTO session ( user_id, session_id)
VALUES ( $1 , $2);
        "#,
    )
    .bind(user_id.0)
    .bind(session_id)
    .execute(&*pool)
    .await;
    match rec {
        Ok(done) => {
            if done.rows_affected() != 1 {
                let uuid = uuid::Uuid::new_v4();
                let details = "session was not created correctly";
                error!("eid: {}, details: {}", uuid, details);
                return Err(AuthStoreError::InternalProblem(
                    uuid.to_string(),
                    details.into(),
                ));
            }
        }
        Err(err) => {
            match filter_user_error(&err) {
                Some(PgUserError::UniqueViolation) => {
                    let uuid = uuid::Uuid::new_v4();
                    let details = "session data was not unique";
                    error!("eid: {}, details: {}", uuid, details);
                    return Err(AuthStoreError::DataNotUnique(
                        uuid.to_string(),
                        details.into(),
                    ));
                }
                _ => {}
            }
            let e: AuthStoreError = err.into();
            error!("eid: {}, DB error at session creation", e.eid());
            return Err(e);
        }
    }
    Ok(())
}

/// Find the user id for a given session id
pub async fn find_user_id_by_session_id(
    pool: Arc<Pool<Postgres>>,
    session_id: &str,
) -> Result<Option<UserId>, AuthStoreError> {
    let res = sqlx::query(
        r#"
SELECT user_id FROM session WHERE session_id = $1;
        "#,
    )
    .bind(&session_id)
    .fetch_one(&*pool)
    .await;
    match res {
        Ok(row) => {
            let user_id: i64 = row.try_get("user_id")?;
            Ok(Some(UserId(user_id)))
        }
        Err(err) => {
            match filter_user_error(&err) {
                Some(PgUserError::DataNotFound) => return Ok(None),
                _ => {}
            }
            let e: AuthStoreError = err.into();
            let eid = e.eid();
            error!("eid: {}, error when finding user_id from session_id", eid);
            return Err(e);
        }
    }
}

/// Delete a session id
pub async fn delete_session(
    pool: Arc<Pool<Postgres>>,
    user_id: &UserId,
) -> Result<(), AuthStoreError> {
    let res = sqlx::query(
        r#"
DELETE FROM session WHERE user_id = $1;
        "#,
    )
    .bind(&user_id.0)
    .execute(&*pool)
    .await;
    match res {
        Ok(_) => {
            return Ok(());
        }
        Err(err) => {
            let e: AuthStoreError = err.into();
            error!("eid: {}, DB error at session delete", e.eid());
            return Err(e);
        }
    }
}
