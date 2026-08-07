pub mod backup;
pub mod bluetooth;
pub mod dashboard;
pub mod datetime;
pub mod hardware;
pub mod logs;
pub mod monitor;
pub mod network;
pub mod services;
pub mod snapshots;
pub mod software;
pub mod storage;
pub mod users;

use crate::layout;

pub(crate) fn error_body(context: &str, detail: impl std::fmt::Display) -> String {
    format!(r#"<p class="error">{context}: {detail}</p>"#)
}

pub(crate) fn render(
    title: &str,
    active_href: &str,
    username: &str,
    body: String,
) -> axum::response::Html<String> {
    axum::response::Html(layout::page(title, active_href, username, &body))
}

pub(crate) fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
