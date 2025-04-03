use actix_web::{App, HttpServer, web};
use dotenv::dotenv;
use crate::core::{database, security::AuthService};
use std::env;

mod core;
mod models;
mod handlers;
mod config;
mod schema;
mod repositories;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let pool = database::create_pool();
    let auth_service = AuthService::new(
        env::var("ACCESS_SECRET").expect("ACCESS_SECRET must be set"),
        env::var("REFRESH_SECRET").expect("REFRESH_SECRET must be set"),
        env::var("ACCESS_EXPIRATION").expect("ACCESS_SECRET must be set").parse::<i64>().unwrap(),
        env::var("REFRESH_EXPIRATION").expect("REFRESH_SECRET must be set").parse::<i64>().unwrap(),
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .configure(config::routes::configure)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
