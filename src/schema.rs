// @generated automatically by Diesel CLI.

diesel::table! {
    refresh_tokens (id) {
        id -> Int4,
        user_id -> Int4,
        token_version -> Int4,
        issued_at -> Timestamp,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        email -> Varchar,
        password_hash -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Nullable<Bool>,
        role -> Nullable<Varchar>,
        email_verified -> Nullable<Bool>,
        refresh_token_version -> Int4,
    }
}

diesel::joinable!(refresh_tokens -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    refresh_tokens,
    users,
);
