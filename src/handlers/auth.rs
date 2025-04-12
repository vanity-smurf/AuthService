use crate::{
    core::{database::DbPool, error::ApiError, security::AuthService},
    models::{auth::*, auth_tokens::RefreshTokenRequest, user::NewUser},
    repositories::{refresh_token_repository::RefreshTokenRepository, user_repository::UserRepository},
};
use actix_web::{
    cookie::{time::Duration as CookieDuration, Cookie, SameSite},
    web, HttpRequest, HttpResponse,
};
use serde_json::json;
use std::num::ParseIntError;

fn extract_refresh_token(
    req: &HttpRequest,
    payload: Option<web::Json<RefreshTokenRequest>>,
) -> Result<String, ApiError> {
    if let Some(cookie) = req.cookie("refresh_token") {
        Ok(cookie.value().to_string())
    } else if let Some(payload) = payload {
        Ok(payload.into_inner().refresh_token)
    } else {
        Err(ApiError::BadRequest("Refresh token not provided".into()))
    }
}

fn verify_token(
    auth_service: &AuthService,
    token: &str,
) -> Result<crate::models::auth_tokens::RefreshClaims, ApiError> {
    auth_service
        .verify_refresh_token(token)
        .map_err(|_| ApiError::Unauthorized)
}

async fn update_tokens_in_db(
    pool: &DbPool,
    subject: &str,
    new_claims: &crate::models::auth_tokens::RefreshClaims,
) -> Result<(), ApiError> {
    RefreshTokenRepository::delete_refresh_token(pool, subject).await?;
    RefreshTokenRepository::create_refresh_token(pool, new_claims).await?;
    Ok(())
}

fn create_refresh_cookie(token: &str, secure: bool) -> Cookie<'static> {
    Cookie::build("refresh_token", token.to_owned())
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .path("/auth/refresh")
        .max_age(CookieDuration::days(30))
        .finish()
}

fn create_clear_cookie() -> Cookie<'static> {
    Cookie::build("refresh_token", "")
        .path("/")
        .max_age(CookieDuration::ZERO)
        .finish()
}

pub async fn register(
    pool: web::Data<DbPool>,
    auth_service: web::Data<AuthService>,
    payload: web::Json<NewUserRequest>,
) -> Result<HttpResponse, ApiError> {
    if payload.email.is_empty() || payload.password.is_empty() {
        return Err(ApiError::BadRequest("Email and password are required".into()));
    }

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

    auth_service
        .verify_password(&payload.password, &user.password_hash)
        .map_err(|_| ApiError::Unauthorized)?;

    let role = user.role.as_deref().unwrap_or("user");
    let (access_token, refresh_token) = auth_service
        .generate_tokens(user.id, &user.email, role)
        .map_err(|_| ApiError::Internal)?;

    let refresh_claims = auth_service
        .verify_refresh_token(&refresh_token)
        .map_err(|_| ApiError::Internal)?;

    RefreshTokenRepository::create_refresh_token(&pool, &refresh_claims).await?;

    let refresh_cookie = create_refresh_cookie(&refresh_token, true);

    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie)
        .json(json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": auth_service.access_expiration
        })))
}

pub async fn logout(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    payload: Option<web::Json<RefreshTokenRequest>>,
) -> Result<HttpResponse, ApiError> {
    let refresh_token = extract_refresh_token(&req, payload)?;
    let claims = verify_token(&auth_service, &refresh_token)?;

    if !RefreshTokenRepository::token_exists(&pool, &claims.sub).await? {
        return Err(ApiError::NotFound);
    }

    RefreshTokenRepository::delete_refresh_token(&pool, &claims.sub).await?;

    let clear_cookie = create_clear_cookie();
    Ok(HttpResponse::NoContent().cookie(clear_cookie).finish())
}

pub async fn refresh_token(
    pool: web::Data<DbPool>,
    auth_service: web::Data<AuthService>,
    req: HttpRequest,
    payload: Option<web::Json<RefreshTokenRequest>>,
) -> Result<HttpResponse, ApiError> {
    let refresh_token = extract_refresh_token(&req, payload)?;
    
    let claims = verify_token(&auth_service, &refresh_token)?;

    if !RefreshTokenRepository::token_exists(&pool, &claims.sub).await? {
        return Err(ApiError::Unauthorized);
    }

    let user_id = claims.sub.parse::<i32>()
        .map_err(|e: ParseIntError| ApiError::BadRequest(e.to_string()))?;
    
    let user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(ApiError::NotFound)?;

        let (access_token, new_refresh_token) = auth_service
        .refresh_tokens(&refresh_token, user)
        .map_err(|_| ApiError::Unauthorized)?;

    let new_claims = auth_service
        .verify_refresh_token(&new_refresh_token)
        .map_err(|_| ApiError::Internal)?;

    update_tokens_in_db(&pool, &claims.sub, &new_claims).await?;

    let refresh_cookie = create_refresh_cookie(&new_refresh_token, false);

    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie)
        .json(json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": auth_service.access_expiration
        })))
}
