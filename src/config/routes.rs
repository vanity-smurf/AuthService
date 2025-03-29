use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    use actix_web_httpauth::middleware::HttpAuthentication;

    cfg.service(
        web::scope("/api")
            .service(
                web::scope("/auth")
                    .route("/register", web::post().to(crate::handlers::auth::register))
                    .route("/login", web::post().to(crate::handlers::auth::login))
            )
            .service(
                web::scope("/protected")
                    .wrap(HttpAuthentication::bearer(|req, _| async {
                        Ok(req)
                    }))
                    .route("", web::get().to(crate::handlers::protected::protected_route))
            )
    );
}
