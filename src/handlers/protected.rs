use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;

use crate::core::{error::ApiError, security::AuthService};

pub async fn protected_route(
    auth_service: web::Data<AuthService>,
    bearer: BearerAuth,
) -> Result<HttpResponse, ApiError> {
    let token = bearer.token();
    let claims = auth_service.verify_token(token)
        .map_err(|_| ApiError::Unauthorized)?;
    
    Ok(HttpResponse::Ok().json(claims))
}
