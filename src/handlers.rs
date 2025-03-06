use crate::db::DbContext;
use crate::models::{NewUser, NewUserRequest};
use actix_web::{web, HttpResponse, Responder};

pub async fn register(
    pool: web::Data<DbContext>,
    new_user_req: web::Json<NewUserRequest>,
) -> impl Responder {
    let new_user_req = new_user_req.into_inner();
    
    match NewUser::new(&new_user_req) {
        Ok(new_user) => match pool.create_user(&new_user) {
            Ok(user) => {
                HttpResponse::Created()
                    .json(format!("User {} created successfully", user.id))
            }
            Err(_) => HttpResponse::InternalServerError()
                .json("Failed to create user"),
        },

        Err(_) => HttpResponse::InternalServerError()
            .json("Invalid input data"),
    }
}

