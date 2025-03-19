use actix_web::web;

use crate::handlers::{register, login, protected};

pub fn config(cfg: &mut web::ServiceConfig) {
    // Group related user routes under the "/users" prefix
    cfg.service(web::scope("/users")
        .configure(user_routes)); // Modularize route configuration
}

fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/register", web::post().to(register))
       .route("/login", web::post().to(login))
       .route("/protected", web::get().to(protected));
}

