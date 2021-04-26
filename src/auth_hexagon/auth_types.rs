use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub type Token = String;
pub type UserId = i64;
pub type SessionToken = String;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct UserProfile {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Credential {
    pub login_name: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Roles {
    Default,
    Admin,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokenClaims {
    pub sub: String,
    pub iss: String,
    pub exp: usize,
    pub iat: usize,
    pub aud: String,
}

impl Display for Roles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = match self {
            Roles::Admin => "admin",
            Roles::Default => "default",
        };
        f.write_str(d)
    }
}
