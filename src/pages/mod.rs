pub mod backup;
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
pub mod terminal;
pub mod users;
pub mod widgets;

use crate::layout;

pub(crate) const ADMINISTRATION_UNAVAILABLE_NOTICE: &str = r#"<p class="notice">As alterações de software e firewall ainda não estão disponíveis pelo painel web. Use o Vega na sessão local.</p>"#;

/// Authentication alone cannot authorize writes through the service account's
/// D-Bus connection. Keep old POST URLs fail-closed until a per-user backend exists.
pub(crate) async fn administration_unavailable(
    axum::extract::Extension(user): axum::extract::Extension<crate::auth::CurrentUser>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> (axum::http::StatusCode, axum::response::Html<String>) {
    eprintln!(
        "vega-web: escrita indisponível usuário={:?} rota={:?} motivo=per-user-authorization-unavailable",
        user.0,
        uri.path()
    );
    (
        axum::http::StatusCode::FORBIDDEN,
        render(
            "Ação indisponível",
            uri.path(),
            &user.0,
            ADMINISTRATION_UNAVAILABLE_NOTICE.to_string(),
        ),
    )
}

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
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
