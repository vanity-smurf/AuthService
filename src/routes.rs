use crate::handlers::{register, login, protected};
use actix_web::web;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/users")
        .route("/register", web::post().to(register))
        .route("/login", web::post().to(login))
        .route("/protected", web::get().to(protected))
        );
}
