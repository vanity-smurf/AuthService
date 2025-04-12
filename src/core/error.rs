use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Authentication failed")]
    Unauthorized,
    #[error("User not found")]
    NotFound,
    #[error("Internal server error")]
    Internal,
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Conflict: {0}")]
    Conflict(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    code: u16,
    error: String,
    message: String,
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let (status, message) = match self {
            ApiError::Unauthorized => (401, "Invalid credentials".to_string()),
            ApiError::NotFound => (404, "Resource not found".to_string()),
            ApiError::Internal => (500, "Internal server error".to_string()),
            ApiError::BadRequest(msg) => (400, msg.clone()),
            ApiError::Conflict(msg) => (409, msg.clone()),
        };

        HttpResponse::build(self.status_code()).json(ErrorResponse {
            code: status,
            error: self.to_string(),
            message,
        })
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            ApiError::Unauthorized => actix_web::http::StatusCode::UNAUTHORIZED,
            ApiError::NotFound => actix_web::http::StatusCode::NOT_FOUND,
            ApiError::Internal => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ApiError::Conflict(_) => actix_web::http::StatusCode::CONFLICT,
        }
    }
}
