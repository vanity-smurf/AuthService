use argon2::password_hash::{Error, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand_core::OsRng;

pub struct PasswordHasherUtil;

pub trait PasswordHandler {
    fn hash_password(password: &str) -> Result<String, Error>;
    fn verify_password(password: &str, hash: &str) -> Result<bool, Error>;
}

impl PasswordHandler for PasswordHasherUtil {
    fn hash_password(password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let hashed_password = argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hashed_password.to_string())
    }

    fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
        let parsed_hash = PasswordHash::new(hash)?;
        let argon2 = Argon2::default();

        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}
