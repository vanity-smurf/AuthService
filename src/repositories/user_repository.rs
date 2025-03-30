use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods, prelude::*};
use crate::{
    schema::users,
    models::user::{User, NewUser, UserChanges},
    core::{error::ApiError, database::DbPool}
};

pub struct UserRepository;

impl UserRepository {
    pub async fn create_user(
        pool: &DbPool,
        new_user: &NewUser,
    ) -> Result<(), ApiError> {
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;
        
        diesel::insert_into(users::table)
            .values(new_user)
            .execute(&mut conn)
            .map_err(|_| ApiError::Internal)?;

        Ok(())
    }

    pub async fn find_by_email(
        pool: &DbPool,
        user_email: &str,
    ) -> Result<Option<User>, ApiError> {
        use crate::schema::users::dsl::*;
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        users
            .filter(email.eq(user_email))
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| match e {
                diesel::result::Error::NotFound => ApiError::Unauthorized,
                _ => ApiError::Internal
            })
    }

    pub async fn find_by_id(
        pool: &DbPool,
        user_id: i32,
    ) -> Result<Option<User>, ApiError> {
        use crate::schema::users::dsl::*;
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        users
            .find(user_id)
            .first::<User>(&mut conn)
            .optional()
            .map_err(|_| ApiError::Internal)
    }

    pub async fn update_user(
        pool: &DbPool,
        user_id: i32,
        changes: &UserChanges,
    ) -> Result<User, ApiError> {
        use crate::schema::users::dsl::*;
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        diesel::update(users.find(user_id))
            .set(changes)
            .get_result(&mut conn)
            .map_err(|_| ApiError::Internal)
    }

    pub async fn delete_user(
        pool: &DbPool,
        user_id: i32,
    ) -> Result<usize, ApiError> {
        use crate::schema::users::dsl::*;
        let mut conn = pool.get().map_err(|_| ApiError::Internal)?;

        diesel::update(users.find(user_id))
            .set(is_active.eq(false))
            .execute(&mut conn)
            .map_err(|_| ApiError::Internal)

        // diesel::delete(users.find(user_id))
        //     .execute(&mut conn)
        //     .map_err(|_| ApiError::Internal)
    }

}
