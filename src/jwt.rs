use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation, TokenData};
use chrono::{Utc, Duration};
use std::env;
use dotenv::dotenv;
use crate::models::Claims;

pub fn get_secret_key() -> String {
    dotenv().ok();
    env::var("JWT_SECRET").expect("JWT_SECRET must be set")
}


pub fn generate_jwt_token(user_id: usize, email: &str, role: &str ) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiration = now + Duration::hours(1);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(get_secret_key().as_ref())
    )
}

pub fn verify_jwt_token(token: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(get_secret_key().as_ref()),
        &validation
    )
}
