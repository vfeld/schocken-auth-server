#[derive(Debug, Clone)]
pub enum PgUserError {
    DataNotFound,
    UniqueViolation,
}

impl std::fmt::Display for PgUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error = match self {
            PgUserError::DataNotFound => format!("Data not found"),
            PgUserError::UniqueViolation => format!("Unique Violation"),
        };
        f.write_str(&error)
    }
}

pub fn filter_user_error(e: &sqlx::Error) -> Option<PgUserError> {
    match e {
        sqlx::Error::Database(s) => match s.code() {
            Some(s) => {
                if s.eq("23505") {
                    return Some(PgUserError::UniqueViolation);
                } else {
                    return None;
                }
            }
            _ => return None,
        },
        sqlx::Error::RowNotFound => Some(PgUserError::DataNotFound),
        _ => None,
    }
}
