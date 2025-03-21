use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

use crate::hasher::PasswordHasherUtil;
use crate::schema::users;
use crate::hasher::PasswordHandler;

#[derive(Debug, Queryable, Insertable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub password_hash: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
    pub is_active: Option<bool>,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct NewUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // ID 
    pub email: String,
    pub role: String,
    pub exp: usize, 
    pub iat: usize,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub email: String,
    pub password_hash: String,
}

impl NewUser {
    pub fn new(req: &NewUserRequest) -> Result<Self, String> {
        match PasswordHasherUtil::hash_password(&req.password) {
            Ok(password_hash) => Ok(Self {
                email: req.email.to_string(),
                password_hash,
            }),
            Err(e) => Err(format!("Password hashing failed: {}", e)),
        }
    }
}
