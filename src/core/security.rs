use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, Error};
use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use jsonwebtoken::errors::Error as JwtError;
use crate::models::user::User;


#[derive(Clone)] 
pub struct AuthService {
    access_secret: String,
    refresh_secret: String,
    access_expiration: i64, // min 
    refresh_expiration: i64 // days
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    sub: String, // ID
    email: String,
    role: String,
    exp: usize, // 15-30 min
    iat: usize 
} 

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    sub: String,
    token_version: u32, // TODO later 
    exp: usize, // 7-30 days
    iat: usize
}

impl AuthService {
    pub fn new(access_secret: String, refresh_secret: String, access_expiration: i64, refresh_expiration: i64) -> Self {
        Self {
            access_secret,
            refresh_secret,
            access_expiration,
            refresh_expiration,
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Error> {
        let parsed_hash = argon2::password_hash::PasswordHash::new(hash)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub fn generate_access_token(&self, user_id: i32, email: &str, role: &str) -> Result<String, JwtError> {
        let now = Utc::now();
        let expiration = now + Duration::minutes(self.access_expiration); // hours
        
        let claims = AccessClaims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: expiration.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.access_secret.as_ref()),
        )
    }

    pub fn generate_refresh_token(&self, user_id: i32) -> Result<String, JwtError> {
        let now = Utc::now();
        let expiration = now + Duration::days(self.refresh_expiration); // days
        
        let claims = RefreshClaims {
            sub: user_id.to_string(),
            token_version: 1,
            exp: expiration.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.refresh_secret.as_ref()),
        )
    }


    pub fn verify_access_token(&self, token: &str) -> Result<AccessClaims, JwtError> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        decode::<AccessClaims>(
            token,
            &DecodingKey::from_secret(self.access_secret.as_ref()),
            &validation,
        ).map(|data| data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshClaims, JwtError> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        decode::<RefreshClaims>(
            token,
            &DecodingKey::from_secret(self.refresh_secret.as_ref()),
            &validation,
        ).map(|data| data.claims)
    }

    pub fn refresh_tokens(&self, refresh_token: &str, user: User) -> Result<(String, String), JwtError> {
        let claims = self.verify_refresh_token(refresh_token)?;
        // generate new pair
        let new_access = self.generate_access_token(user.id, &user.email, user.role.as_deref().unwrap_or("user") )?;
        let new_refresh = self.generate_refresh_token(user.id)?;
        
        Ok((new_access, new_refresh))
    }
}
