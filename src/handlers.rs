use crate::db::DbContext;
use crate::models::{NewUser, NewUserRequest, AuthRequest};
use crate::jwt::{generate_jwt_token, verify_jwt_token};

use actix_web::{web, HttpResponse, Responder, HttpRequest};
use actix_web::http::header::AUTHORIZATION;
use actix_web::cookie::Cookie;
use log::{error, info};

pub async fn register(
    pool: web::Data<DbContext>,
    new_user_req: web::Json<NewUserRequest>,
) -> impl Responder {
    let new_user_req = new_user_req.into_inner();
    
    match NewUser::new(&new_user_req) {
        Ok(new_user) => match pool.create_user(&new_user) {
            Ok(user) => {
                info!("User {} created successfully", user.id);
                HttpResponse::Created().json(format!("User {} created successfully", user.id))
            }
            Err(e) => {
                error!("Failed to create user: {:?}", e);
                HttpResponse::InternalServerError().json("Failed to create user")
            }
        },

        Err(e) => {
            error!("Invalid input data: {:?}", e);
            HttpResponse::BadRequest().json("Invalid input data")
        }
    }
}

pub async fn login(
    pool: web::Data<DbContext>,
    login_data: web::Json<AuthRequest>
) -> impl Responder {
    let login_data = login_data.into_inner();

    match pool.verify_user(&login_data) {
        Ok(user) => {
            let role = match &user.role {
                Some(role) => role.as_str(),
                None => "user",  // Роль по умолчанию
            };

            match generate_jwt_token(user.id as usize, &user.email, role) {
                Ok(token) => {
                    info!("User {} logged in successfully", user.id);
                    HttpResponse::Ok()
                        .cookie(
                            Cookie::build("token", token.clone())
                                .http_only(true)
                                .secure(true)
                                .finish(),
                        )
                        .insert_header(("Authorization", format!("Bearer {}", token)))
                        .json(serde_json::json!({ "token": token }))
                }
                Err(e) => {
                    error!("JWT generation failed: {:?}", e);
                    HttpResponse::InternalServerError().json("Failed to generate token")
                }
            }
        }

        Err(_) => {
            error!("Invalid login attempt");
            HttpResponse::Unauthorized().json("Invalid email or password")
        }
    }
}

pub async fn protected(req: HttpRequest) -> impl Responder {
    if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            let token = auth_str.trim_start_matches("Bearer ").to_string();

            match verify_jwt_token(&token) {
                Ok(data) => {
                    info!("User {} accessed protected route", data.claims.sub);
                    HttpResponse::Ok().json(data.claims)
                }
                Err(_) => {
                    error!("Invalid token");
                    HttpResponse::Unauthorized().json("Invalid token")
                }
            }
        } else {
            error!("Malformed Authorization header");
            HttpResponse::Unauthorized().json("Invalid Authorization header")
        }
    } else {
        error!("No Authorization header found");
        HttpResponse::Unauthorized().json("Authorization required")
    }
}
