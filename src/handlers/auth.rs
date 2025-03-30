use actix_web::{web, HttpResponse};
use serde_json::json;
use crate::{
    core::{database::DbPool, error::ApiError, security::AuthService},
    models::{auth::*, user::NewUser},
    repositories::user_repository::UserRepository
};

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

    UserRepository::create_user(&pool, &new_user).await?;

    Ok(HttpResponse::Created().json(json!({
        "message": "User registered successfully"
    })))
}

pub async fn login(
    pool: web::Data<DbPool>,
    auth_service: web::Data<AuthService>,
    payload: web::Json<AuthRequest>,
) -> Result<HttpResponse, ApiError> {
    let user = UserRepository::find_by_email(&pool, &payload.email)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    

    let valid = &auth_service.verify_password(&payload.password, &user.password_hash).unwrap();

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
