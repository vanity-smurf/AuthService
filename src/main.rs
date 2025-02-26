use crate::db::DbContext;
use crate::models::NewUser;
use crate::hasher::{PasswordHasherUtil, PasswordHandler};

mod db;
mod hasher;
mod models;
mod schema;

fn main() {
    let new_user = NewUser::new("example@mail", "password");
    let mut db = DbContext::new();

    let user = db.create_user(&new_user).unwrap();
    println!("User created: {:?}", user);
    let id = db.delete_user(user.id).unwrap();
    println!("Id deleted {}", id);

    let password = "my_secure_password";

    let hashed_password = PasswordHasherUtil::hash_password(password).unwrap();
    let is_valid = PasswordHasherUtil::verify_password(password, &hashed_password).unwrap();

    println!("Hashed Password: {}", hashed_password);
    println!("Password is valid: {}", is_valid);
}
