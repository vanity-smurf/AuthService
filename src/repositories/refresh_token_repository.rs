use crate::{
    core::{database::DbPool, error::ApiError},
    models::auth_tokens::RefreshClaims,
    schema::refresh_tokens::dsl::*,
};
use diesel::{
    delete, dsl::count, insert_into, query_dsl::QueryDsl, ExpressionMethods,
    RunQueryDsl,
};

pub struct RefreshTokenRepository;

impl RefreshTokenRepository {
    pub async fn create_refresh_token(
        pool: &DbPool,
        claims: &RefreshClaims,
    ) -> Result<(), ApiError> {
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        insert_into(refresh_tokens)
            .values(claims)
            .execute(&mut conn)
            .map_err(|_| ApiError::Internal)?;

        Ok(())
    }

    pub async fn delete_refresh_token(pool: &DbPool, subject: &str) -> Result<(), ApiError> {
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        delete(refresh_tokens)
            .filter(sub.eq(subject))
            .execute(&mut conn)
            .map_err(|_| ApiError::Internal)?;

        Ok(())
    }

    pub async fn token_exists(pool: &DbPool, subject: &str) -> Result<bool, ApiError> {
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        let count: i64 = refresh_tokens
            .filter(sub.eq(subject))
            .select(count(id))
            .first(&mut conn)
            .map_err(|_| ApiError::Internal)?;

        Ok(count > 0)
    }

    pub async fn delete_all_for_user(pool: &DbPool, subject: &str) -> Result<(), ApiError> {
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        delete(refresh_tokens)
            .filter(sub.eq(subject))
            .execute(&mut conn)
            .map_err(|_| ApiError::Internal)?;

        Ok(())
    }
}
