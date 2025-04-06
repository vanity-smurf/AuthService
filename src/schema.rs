// @generated automatically by Diesel CLI.

diesel::table! {
    refresh_tokens (id) {
        id -> Int4,
        sub -> Varchar,
        token_version -> Int4,
        exp -> Int8,
        iat -> Int8,
        created_at -> Nullable<Timestamp>,
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

diesel::allow_tables_to_appear_in_same_query!(
    refresh_tokens,
    users,
);
