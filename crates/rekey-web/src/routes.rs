use axum::{
    Router,
    body::Body,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
};
use rust_embed::Embed;
use serde_json::json;
use std::sync::Arc;

#[derive(Embed)]
#[folder = "assets/"]
struct Assets;

pub struct WebState {
    pub db_path: String,
}

pub fn api_router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/api/secrets", get(list_secrets))
        .route("/api/audit", get(list_audit))
        .route("/api/stats", get(get_stats))
        .route("/dashboard/{*path}", get(serve_dashboard))
        .route(
            "/dashboard",
            get(|| async { axum::response::Redirect::to("/dashboard/index.html") }),
        )
        .with_state(state)
}

async fn list_secrets(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let conn = match rusqlite::Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            );
        }
    };
    match rekey_vault::secrets::list_secrets(&conn) {
        Ok(secrets) => (StatusCode::OK, Json(json!(secrets))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn list_audit(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let conn = match rusqlite::Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            );
        }
    };
    match rekey_vault::audit::query_audit(&conn, None, None, 200) {
        Ok(logs) => (StatusCode::OK, Json(json!(logs))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

async fn get_stats(State(state): State<Arc<WebState>>) -> impl IntoResponse {
    let conn = match rusqlite::Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            );
        }
    };

    let today_start = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        now - (now % 86400)
    };

    let total_today: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1",
            [today_start],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let errors_today: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1 AND (status_code >= 400 OR status_code IS NULL)",
            [today_start],
            |r| r.get(0),
        )
        .unwrap_or(0);

    (
        StatusCode::OK,
        Json(json!({
            "today_requests": total_today,
            "today_errors": errors_today,
        })),
    )
}

async fn serve_dashboard(axum::extract::Path(path): axum::extract::Path<String>) -> Response<Body> {
    let path = if path.is_empty() {
        "index.html".to_string()
    } else {
        path
    };
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            Response::builder()
                .header("content-type", mime.as_ref())
                .body(Body::from(content.data.to_vec()))
                .unwrap_or_else(|_| Response::new(Body::from("internal error")))
        }
        None => Response::builder()
            .status(404)
            .body(Body::from("not found"))
            .unwrap_or_else(|_| Response::new(Body::from("not found"))),
    }
}
