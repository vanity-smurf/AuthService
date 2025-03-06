use crate::models::{NewUser, User};
use crate::schema::users;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;
use dotenv::dotenv;
use std::env;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct DbContext {
    pub pool: DbPool,
}

impl DbContext {
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

    pub fn get_conn(&self) -> PooledConnection<ConnectionManager<PgConnection>> {
        self.pool.get().expect("Failed to get DB connection")
    }

    pub fn create_user(&self, new_user: &NewUser) -> Result<User, diesel::result::Error> {
        let mut conn = self.get_conn();

        diesel::insert_into(users::table)
            .values(new_user)
            .get_result(&mut conn)
    }

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
}
