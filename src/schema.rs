// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Int4,
        #[max_length = 255]
        email -> Varchar,
        #[max_length = 255]
        password_hash -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Nullable<Bool>,
        #[max_length = 50]
        role -> Nullable<Varchar>,
    }
}
