use diesel::{insert_into, RunQueryDsl};
use crate::schema::refresh_tokens;
use crate::models::auth_tokens::RefreshClaims;
use crate::core::{error::ApiError, database::DbPool};

pub struct RefreshTokenRepository;

impl RefreshTokenRepository {
    pub async fn create_refresh_token(
        pool: &DbPool,
        new_refresh_claims: &RefreshClaims,
    ) -> Result<(), ApiError> {
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        insert_into(refresh_tokens::table)
            .values(new_refresh_claims)
            .execute(&mut conn)
            .map_err(|_| ApiError::Internal)?;

        Ok(())
    }
}

