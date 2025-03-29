use actix_web::{web, HttpResponse};
use diesel::{RunQueryDsl, QueryDsl, ExpressionMethods};
use serde_json::json;

use crate::core::{database::DbPool, error::ApiError, security::AuthService};
use crate::models::{auth::*, user::NewUser};
use crate::schema::users;

pub async fn register(
    pool: web::Data<DbPool>,
    auth_service: web::Data<AuthService>,
    payload: web::Json<NewUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let password_hash = auth_service
        .hash_password(&payload.password)
        .map_err(|_| ApiError::Internal)?;

    let new_user = NewUser {
        email: payload.email.clone(),
        password_hash,
        is_active: Some(true),
        role: Some("user".to_string()),
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&mut pool.get().map_err(|_| ApiError::Internal)?)
        .map_err(|_| ApiError::Internal)?;

    Ok(HttpResponse::Created().json(json!({
        "message": "User registered successfully"
    }))) // Исправлено количество скобок
}

pub async fn login(
    pool: web::Data<DbPool>,
    auth_service: web::Data<AuthService>,
    payload: web::Json<AuthRequest>,
) -> Result<HttpResponse, ApiError> {
    use crate::schema::users::dsl::*;

    let mut conn = pool.get().map_err(|_| ApiError::Internal)?;
    
    let user = users
        .filter(email.eq(&payload.email))
        .first::<crate::models::user::User>(&mut conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => ApiError::Unauthorized,
            _ => ApiError::Internal,
        })?;

    let valid = auth_service
        .verify_password(&payload.password, &user.password_hash)
        .map_err(|_| ApiError::Internal)?;

    if !valid {
        return Err(ApiError::Unauthorized);
    }

    let token = auth_service
        .generate_token(
            &user.id.to_string(),
            &user.email,
            user.role.as_deref().unwrap_or("user"),
        )
        .map_err(|_| ApiError::Internal)?;

    Ok(HttpResponse::Ok().json(json!({
        "token": token
    })))
}
