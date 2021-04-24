use std::sync::Arc;

use super::pg_error_mapping::PgUserError;
use log::error;
use sqlx::Row;
use sqlx::{postgres::PgRow, FromRow, Pool, Postgres};

use super::super::auth_types::*;
use super::{super::auth_store_port::AuthStoreError, pg_error_mapping::filter_user_error};

pub async fn has_token(pool: Arc<Pool<Postgres>>, token: &Token) -> Result<(), AuthStoreError> {
    let rec = sqlx::query(
        r#"
SELECT token FROM day0_token WHERE token = $1;
        "#,
    )
    .bind(token)
    .execute(&*pool)
    .await;
    match rec {
        Ok(done) => {
            if done.rows_affected() > 0 {
                return Ok(());
            }
        }
        Err(err) => {
            let e: AuthStoreError = err.into();
            error!("eid: {}, day0 token can not be set", e.eid());
            return Err(e);
        }
    }
    Ok(())
}

pub async fn insert_day0_token(
    pool: Arc<Pool<Postgres>>,
    token: &Token,
) -> Result<(), AuthStoreError> {
    let rec = sqlx::query(
        r#"
INSERT INTO day0_token ( token, valid)
VALUES ( $1 , $2);
        "#,
    )
    .bind(token)
    .bind(true)
    .execute(&*pool)
    .await;
    match rec {
        Ok(done) => {
            if done.rows_affected() != 1 {
                let uuid = uuid::Uuid::new_v4();
                let details = "day0 token was not created correctly";
                error!("eid: {}, details: {}", uuid, details);
                return Err(AuthStoreError::InternalProblem(
                    uuid.to_string(),
                    details.into(),
                ));
            }
        }
        Err(err) => {
            match filter_user_error(&err) {
                Some(PgUserError::UniqueViolation) => return Ok(()),
                _ => {}
            }
            let e: AuthStoreError = err.into();
            error!("eid: {}, DB error at day0 token creation", e.eid());
            return Err(e);
        }
    }
    Ok(())
}

/// Return the validation time of the day0 token or an error in case it was not valid or not found
pub async fn get_day0_token_data(
    pool: Arc<Pool<Postgres>>,
    token: &Token,
) -> Result<time::OffsetDateTime, AuthStoreError> {
    let res = sqlx::query(
        r#"
SELECT valid, created_at FROM day0_token WHERE token = $1;
        "#,
    )
    .bind(&token)
    .fetch_one(&*pool)
    .await;
    match res {
        Ok(row) => {
            let valid: bool = row.try_get("valid")?;
            let created_at: time::OffsetDateTime = row.try_get("created_at")?;
            if valid {
                return Ok(created_at);
            } else {
                let eid = uuid::Uuid::new_v4();
                let details = "invalid day0 token";
                error!("eid: {}, details: {}", eid, details);
                return Err(AuthStoreError::InvalidOneTimeToken(
                    eid.to_string(),
                    details.into(),
                ));
            }
        }
        Err(err) => {
            match filter_user_error(&err) {
                Some(PgUserError::DataNotFound) => {
                    let eid = uuid::Uuid::new_v4();
                    let details = "day0 token not found";
                    error!("eid: {}, details: {}", eid, details);
                    return Err(AuthStoreError::InvalidOneTimeToken(
                        eid.to_string(),
                        details.into(),
                    ));
                }
                _ => {}
            }
            let e: AuthStoreError = err.into();
            let eid = e.eid();
            error!("eid: {}, error when fetching day0 token", eid);
            return Err(e);
        }
    }
}

pub async fn invalidate_day0_token(
    pool: Arc<Pool<Postgres>>,
    token: &Token,
) -> Result<(), AuthStoreError> {
    let rec = sqlx::query(
        r#"
UPDATE day0_token SET valid = false WHERE token = $1;
        "#,
    )
    .bind(token)
    .execute(&*pool)
    .await;
    match rec {
        Ok(done) => {
            if done.rows_affected() != 1 {
                let uuid = uuid::Uuid::new_v4();
                let details = "day0 token not updated correctly";
                error!("eid: {}, details: {}", uuid, details);
                return Err(AuthStoreError::InternalProblem(
                    uuid.to_string(),
                    details.into(),
                ));
            }
        }
        Err(err) => {
            let e: AuthStoreError = err.into();
            error!("eid: {}, DB error at day0 token update", e.eid());
            return Err(e);
        }
    }
    Ok(())
}

pub async fn create_user_id(pool: Arc<Pool<Postgres>>) -> Result<UserId, AuthStoreError> {
    #[derive(sqlx::FromRow, Debug)]
    struct UserIdRes {
        user_id: UserId,
    }

    let rec: PgRow = sqlx::query(
        r#"
INSERT INTO user_id (user_id) VALUES (DEFAULT) RETURNING user_id;
        "#,
    )
    .fetch_one(&*pool)
    .await?;
    let u: UserIdRes = FromRow::from_row(&rec).unwrap();
    Ok(u.user_id)
}

pub async fn insert_credential(
    pool: Arc<Pool<Postgres>>,
    user_id: UserId,
    login_name: &str,
    password_hash: &[u8]
) -> Result<(), AuthStoreError> {
    let rec = sqlx::query(
        r#"
INSERT INTO credentials ( user_id, login_name, pwd_hash)
VALUES ( $1 , $2, $3);
        "#,
    )
    .bind(&user_id)
    .bind(login_name)
    .bind(password_hash)
    .execute(&*pool)
    .await;
    match rec {
        Ok(done) => {
            if done.rows_affected() != 1 {
                let uuid = uuid::Uuid::new_v4();
                let details = "credential was not created correctly";
                error!("eid: {}, details: {}", uuid, details);
                return Err(AuthStoreError::InternalProblem(
                    uuid.to_string(),
                    details.into(),
                ));
            }
        }
        Err(err) => {
            let e: AuthStoreError = err.into();
            let details = "DB error at credential creation";
            error!("eid: {}, details: {}", e.eid(), details);
            return Err(e);
        }
    }
    Ok(())
}

pub async fn insert_user_profile(
    pool: Arc<Pool<Postgres>>,
    user_id: UserId,
    user: &UserProfile,
) -> Result<(), AuthStoreError> {
    let rec = sqlx::query(
        r#"
INSERT INTO user_profile ( user_id, email, first_name, last_name )
VALUES ( $1 , $2, $3, $4);
        "#,
    )
    .bind(&user_id)
    .bind(&user.email)
    .bind(&user.first_name)
    .bind(&user.last_name)
    .execute(&*pool)
    .await;
    match rec {
        Ok(done) => {
            if done.rows_affected() != 1 {
                let uuid = uuid::Uuid::new_v4();
                let details = "user profile not created correctly";
                error!("eid: {}, details: {}", uuid, details);
                return Err(AuthStoreError::InternalProblem(
                    uuid.to_string(),
                    details.into(),
                ));
            }
        }
        Err(err) => {
            let e: AuthStoreError = err.into();
            error!("eid: {}, DB error at user profile creation", e.eid());
            return Err(e);
        }
    }
    Ok(())
}

pub async fn insert_roles(
    pool: Arc<Pool<Postgres>>,
    user_id: UserId,
    roles: &Vec<Roles>,
) -> Result<(), AuthStoreError> {
    for role in roles {
        let rec = sqlx::query(
            r#"
INSERT INTO role_binding ( binding_id, user_id, role_name )
VALUES ( DEFAULT , $1, $2);
            "#,
        )
        .bind(&user_id)
        .bind(&role.to_string())
        .execute(&*pool)
        //.fetch_one(&pool)
        .await;
        match rec {
            Ok(done) => {
                if done.rows_affected() != 1 {
                    let uuid = uuid::Uuid::new_v4();
                    let details = "user profile not created correctly";
                    error!("eid: {}, details: {}", uuid, details);
                    return Err(AuthStoreError::InternalProblem(
                        uuid.to_string(),
                        details.into(),
                    ));
                }
            }
            Err(err) => {
                let e: AuthStoreError = err.into();
                error!("eid: {}, DB error at user profile creation", e.eid());
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Return the validation time of the day0 token or an error in case it was not valid or not found
pub async fn get_pwd_hash(
    pool: Arc<Pool<Postgres>>,
    login_name: &str,
) -> Result<(UserId,Vec<u8>), AuthStoreError> {
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
            Ok((user_id,pwd_hash))
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
