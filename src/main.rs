use actix_web::{App, HttpServer, web};
use dotenv::dotenv;
use crate::core::{database, security::AuthService};

mod core;
mod models;
mod handlers;
mod config;
mod schema;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let pool = database::create_pool();
    let auth_service = AuthService::new(
        std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
        24 // 24 hours expiration
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
