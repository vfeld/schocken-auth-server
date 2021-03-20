use std::fmt::Display;

pub type Token = String;
pub type UserId = i64;

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

impl Display for Roles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = match self {
            Roles::Admin => "admin",
            Roles::Default => "default",
        };
        f.write_str(d)
    }
}
