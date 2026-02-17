use axum::Router;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;

use crate::api::RouterState;

/// Content embedded at compile time
const INDEX_HTML: &str = include_str!("docs.html");
const API_DOCS: &str = include_str!("../../../API_DOCUMENTATION.md");
const API_CHANGELOG: &str = include_str!("../../../API_CHANGELOG.md");

/// Handler for the documentation index page
async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Handler for raw API endpoints markdown
async fn endpoints_md() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/markdown; charset=utf-8")], API_DOCS)
}

/// Handler for raw changelog markdown
async fn changelog_md() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/markdown; charset=utf-8")], API_CHANGELOG)
}

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/docs/endpoints.md", get(endpoints_md))
        .route("/docs/changelog.md", get(changelog_md))
}
