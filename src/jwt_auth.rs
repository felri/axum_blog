use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use sqlx::postgres::PgPool;

use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Serialize;

use crate::{
    model::{TokenClaims, User},
    AppState,
};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: &'static str,
    pub message: String,
}

pub async fn auth(
    cookie_jar: CookieJar,
    State(pool): State<Arc<PgPool>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, ErrorResponse)> {
    let token = cookie_jar.get("token").map(|c| c.value().to_string());

    let token = token.ok_or(|| {
        let json_error = ErrorResponse {
            status: "error",
            message: "Unauthorized".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    });

    let claims = decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(data.jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|e| {
        let json_error = ErrorResponse {
            status: "error",
            message: e.to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?
    .claims;

    let user_id = uuid::Uuid::parse_str(&claims.sub).map_err(|e| {
        let json_error = ErrorResponse {
            status: "error",
            message: e.to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, name, email, password, role, photo, verified, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        let json_error = ErrorResponse {
            status: "error",
            message: e.to_string(),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
    })?;

    let user = user.ok_or_else(|| {
        let json_error = ErrorResponse {
            status: "error",
            message: "User not found".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
