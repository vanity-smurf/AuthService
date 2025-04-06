use diesel::{Queryable, Insertable, AsChangeset};
use serde::Serialize;
use chrono::NaiveDateTime;


#[derive(Debug, Queryable, Serialize)]
pub struct User {
    pub id: i32,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub is_active: Option<bool>,
    pub role: Option<String>,
    pub email_verified: Option<bool>, 
    pub refresh_token_version: i32,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub email: String,
    pub password_hash: String,
    pub is_active: Option<bool>,
    pub role: Option<String>,
}

#[derive(AsChangeset, Debug)]
#[diesel(table_name = crate::schema::users)]
pub struct UserChanges {
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
}
