use std::env;

use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;
use dotenv::dotenv;

use crate::hasher::{PasswordHasherUtil, PasswordHandler};
use crate::models::{NewUser, User, AuthRequest};
use crate::schema::users;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct DbContext {
    pub pool: DbPool,
}

impl DbContext {
    /// Create a new database context with a connection pool
    pub fn new() -> Self {
        dotenv().ok();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let manager = ConnectionManager::<PgConnection>::new(database_url);

        let pool = Pool::builder()
            .max_size(10)
            .build(manager)
            .expect("Failed to create DB pool");

        Self { pool }
    }

    /// Retrieves a pooled database connection
    pub fn get_conn(&self) -> PooledConnection<ConnectionManager<PgConnection>> {
        self.pool.get().expect("Failed to get DB connection")
    }
    
    /// Creates a new user in the database
    pub fn create_user(&self, new_user: &NewUser) -> Result<User, diesel::result::Error> {
        let mut conn = self.get_conn();

        diesel::insert_into(users::table)
            .values(new_user)
            .get_result(&mut conn)
    }
    
    /// Deletes a user by ID from the database
    pub fn delete_user(&self, user_id: i32) -> Result<i32, diesel::result::Error> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_conn();

        let deleted_count = diesel::delete(users.filter(id.eq(user_id))).execute(&mut conn)?;

        if deleted_count == 0 {
            Err(diesel::result::Error::NotFound)
        } else {
            Ok(user_id)
        }
    }
    
    /// Verifies user credentials
    pub fn verify_user(&self, auth_req: &AuthRequest) -> Result<User, String> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_conn();

        let user: User = users
            .filter(email.eq(&auth_req.email))
            .first::<User>(&mut conn)
            .map_err(|_| "User not found".to_string())?;

        let is_valid = PasswordHasherUtil::verify_password(&auth_req.password, &user.password_hash)
            .map_err(|_| "Password verification failed".to_string())?;

        if is_valid {
            Ok(user)
        } else {
            Err("Invalid password".to_string())
        }
    }
}
