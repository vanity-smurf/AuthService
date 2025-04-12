use diesel::Insertable;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String, // ID
    pub email: String,
    pub role: String,
    pub exp: usize, // 15-30 min
    pub iat: usize,
}

#[derive(Debug, Serialize, Deserialize, Insertable)]
#[diesel(table_name = crate::schema::refresh_tokens)]
pub struct RefreshClaims {
    pub sub: String,
    pub token_version: i32, // TODO later
    pub exp: i64,           // 7-30 days
    pub iat: i64,
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}
