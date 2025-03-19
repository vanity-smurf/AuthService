use actix_web::{web, HttpResponse, Responder, HttpRequest};
use actix_web::http::header::AUTHORIZATION;
use actix_web::cookie::Cookie;
use serde::Serialize;

use crate::db::DbContext;
use crate::models::{NewUser, NewUserRequest, AuthRequest};
use crate::jwt::{generate_jwt_token, verify_jwt_token};

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// POST /register - Register a new user
pub async fn register(
    pool: web::Data<DbContext>,
    new_user_req: web::Json<NewUserRequest>,
) -> impl Responder {
    let new_user_req = new_user_req.into_inner();

    let new_user = match NewUser::new(&new_user_req) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid input data".to_string(),
            });
        }
    };

    match pool.create_user(&new_user) {
        Ok(user) => HttpResponse::Created().json(serde_json::json!({ "user_id": user.id })),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Failed to create user".to_string(),
        }),
    }
}

/// POST /login - Authenticate and get JWT token
pub async fn login(
    pool: web::Data<DbContext>,
    login_data: web::Json<AuthRequest>,
) -> impl Responder {
    let login_data = login_data.into_inner();

    match pool.verify_user(&login_data) {
        Ok(user) => {
            let role = user.role.as_deref().unwrap_or("user");

            match generate_jwt_token(user.id as usize, &user.email, role) {
                Ok(token) => HttpResponse::Ok()
                    .cookie(
                        Cookie::build("token", token.clone())
                            .http_only(true)
                            .secure(true)
                            .finish(),
                    )
                    .insert_header(("Authorization", format!("Bearer {}", token)))
                    .json(serde_json::json!({ "token": token })),
                Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to generate token".to_string(),
                }),
            }
        }
        Err(_) => HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid email or password".to_string(),
        }),
    }
}

/// GET /protected - Access protected route with JWT validation
pub async fn protected(req: HttpRequest) -> impl Responder {
    if let Some(token) = extract_bearer_token(&req) {
        match verify_jwt_token(&token) {
            Ok(data) => HttpResponse::Ok().json(data.claims),
            Err(_) => HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Invalid or expired token".to_string(),
            }),
        }
    } else {
        HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Authorization required".to_string(),
        })
    }
}
