use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub type Token = String;
//pub type SessionToken = String;
pub type CsrfToken = String;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct SessionToken(pub String);

#[derive(Default, Debug, Clone, PartialEq)]
pub struct UserId(pub i64);

#[derive(Default, Debug, Clone, PartialEq)]
pub struct ValidateCsrf;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct AllowedOrigin {
    pub origin: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserProfile {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub login_name: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Role {
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

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub pem_key_filename: String,
    pub pem_cert_filename: String,
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = match self {
            Role::Admin => "admin",
            Role::Default => "default",
        };
        f.write_str(d)
    }
}
