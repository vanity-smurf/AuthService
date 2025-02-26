use crate::models::{NewUser, User};
use crate::schema::users;
use diesel::prelude::*;
use diesel::PgConnection;
use dotenv::dotenv;
use std::env;

pub struct DbContext {
    pub conn: PgConnection, // Connection to PostgreSQL database
}

impl DbContext {
    /// Create a new DbContext
    pub fn new() -> Self {
        dotenv().ok();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let conn = PgConnection::establish(&database_url)
            .expect(&format!("Error connecting to {}", database_url));

        Self { conn }
    }

    /// Create a new user in the DB
    pub fn create_user(&mut self, new_user: &NewUser) -> Result<User, diesel::result::Error> {
        diesel::insert_into(users::table)
            .values(new_user)
            .get_result(&mut self.conn) // Use self.conn for the database connection
            .map_err(|e| e) // Return error if insertion fails
    }

    /// Delete a user by their ID
    pub fn delete_user(&mut self, user_id: i32) -> Result<i32, diesel::result::Error> {
        use crate::schema::users::dsl::*;

        // Execute delete query
        let deleted_count = diesel::delete(users.filter(id.eq(user_id))).execute(&mut self.conn)?;

        if deleted_count == 0 {
            Err(diesel::result::Error::NotFound) // Return error if no rows were affected
        } else {
            Ok(user_id)
        }
    }
}
