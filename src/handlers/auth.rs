use actix_web::{
    cookie::{time::Duration as CookieDuration, Cookie, SameSite},
    web, HttpResponse};
use serde_json::json;
use crate::{
    core::{database::DbPool, error::ApiError, security::AuthService},
    models::{auth::*, user::NewUser},
    repositories::{
        user_repository::UserRepository,
        refresh_token_repository::RefreshTokenRepository
    }
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

    //let access_token = auth_service
    //    .generate_access_token(
    //        user.id,
    //        &user.email,
    //        user.role.as_deref().unwrap_or("user")
    //    )
    //    .map_err(|_| ApiError::Internal)?;
    //
    //let refresh_token = auth_service
    //    .generate_refresh_token(
    //        user.id,
    //    )
    //    .map_err(|_| ApiError::Internal)?;
    

    let (access_token, refresh_token) = auth_service
        .generate_tokens(
            user.id, &user.email, user.role.as_deref().unwrap_or("user")
        )
        .map_err(|_| ApiError::Internal)?;

    let refresh_claims = auth_service
        .verify_refresh_token(&refresh_token) 
        .map_err(|_| ApiError::Internal)?;

    RefreshTokenRepository::create_refresh_token(&pool, &refresh_claims);
    
    let refresh_cookie = Cookie::build("refresh_token", refresh_token)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/auth/refresh")
        .max_age(CookieDuration::days(30))
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie)
        .json(json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": auth_service.access_expiration * 60, // sec 
        })))
}
