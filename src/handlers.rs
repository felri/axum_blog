use std::sync::Arc;

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use axum::{
    extract::State,
    http::{header, Response, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OsRng;
use serde_json::json;
use sqlx::postgres::PgPool;

use crate::{
    model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User},
    response::FilteredUser,
    AppState,
};

fn filtered_user(user: User) -> FilteredUser {
    FilteredUser {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        photo: user.photo,
        verified: user.verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}

fn register_user_handler(
    State(pool): AppState<Arc<PgPool>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user_exists = sqlx::query_scalar("SELECT EXISTS (1 FROM users WHERE email = $1)")
        .bing(body.email.to_owned().to_ascii_lowercase())
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
              "status": "fail",
              "message": format!("Database error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        });

    if Some(exists) = user_exists {
        if exists {
            let error_response = serde_json::json!({
              "status": "fail",
              "message": "User with that email already exists",
            });

            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hashed_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",
        body.name.to_string(),
        body.email.to_string(),
        hashed_password,
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
          "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let user_response = serde_json::json!({
      "status": "success",
      "data": serde_json::json!({
          "user": filter_user_record(&user)
      })
    });

    Ok(Json(user_response))
}
