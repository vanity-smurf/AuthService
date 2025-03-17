use crate::db::DbContext;
use actix_web::web::Data;
use actix_web::{App, HttpServer};

mod db;
mod handlers;
mod hasher;
mod models;
mod routes;
mod schema;
mod jwt;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = Data::new(DbContext::new());

    HttpServer::new(move || App::new().app_data(pool.clone()).configure(routes::config))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
