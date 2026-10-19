pub mod admin;
pub mod backup;
pub mod dashboard;
pub mod datetime;
pub mod hardware;
pub mod logs;
pub mod monitor;
pub mod network;
pub mod nvidia;
pub mod services;
pub mod snapshots;
pub mod software;
pub mod storage;
pub mod terminal;
pub mod users;
pub mod widgets;

use crate::layout;

pub(crate) const ADMINISTRATION_UNAVAILABLE_NOTICE: &str = r#"<p class="notice">As alterações pelo painel estão desativadas nesta instalação: o broker administrativo (vega-web-admin.socket) não está configurado. Use o Vega na sessão local ou pelo terminal.</p>"#;

/// Authentication alone cannot authorize writes through the service account's
/// D-Bus connection. Keep old POST URLs fail-closed until a per-user backend exists.
pub(crate) async fn administration_unavailable(
    axum::extract::Extension(user): axum::extract::Extension<crate::auth::CurrentUser>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> (axum::http::StatusCode, axum::response::Html<String>) {
    eprintln!(
        "vega-web: escrita indisponível usuário={:?} rota={:?} motivo=per-user-authorization-unavailable",
        user.name,
        uri.path()
    );
    (
        axum::http::StatusCode::FORBIDDEN,
        render(
            "Ação indisponível",
            uri.path(),
            &user,
            ADMINISTRATION_UNAVAILABLE_NOTICE.to_string(),
        ),
    )
}

/// A failed query, in human terms. The raw daemon error stays available in a
/// collapsed detail block instead of being the message itself.
pub(crate) fn error_body(context: &str, detail: impl std::fmt::Display) -> String {
    let raw = detail.to_string();
    let lower = raw.to_lowercase();
    let (level, explanation) = if lower.contains("authorizationfailed")
        || lower.contains("not authorized")
        || lower.contains("notauthorized")
    {
        (
            "warn",
            "Esta consulta exige autorização de administrador, que o painel ainda não repassa para leituras. Use o console (vega) ou o terminal web.",
        )
    } else if lower.contains("capabilityunavailable") || lower.contains("not supported") {
        ("info", "Recurso não disponível nesta edição.")
    } else if lower.contains("snapper") {
        (
            "info",
            "Snapshots exigem Btrfs com Snapper; esta instalação usa outro sistema de arquivos.",
        )
    } else if lower.contains("not activatable") || lower.contains("was not provided by any") {
        (
            "error",
            "O serviço vegad não está disponível. Verifique se vegad.service está instalado e ativo.",
        )
    } else if lower.contains("timed out") || lower.contains("did not receive a reply") {
        (
            "warn",
            "O vegad não respondeu a tempo. Tente de novo em instantes.",
        )
    } else {
        ("error", "A consulta falhou.")
    };
    format!(
        r#"<div class="notice {level}"><strong>{context}</strong><span>{explanation}</span><details><summary>Detalhes técnicos</summary><code>{}</code></details></div>"#,
        html_escape(&raw)
    )
}

/// The session's CSRF token for forms the page renders, or `None` when the
/// session vanished (the request would be redirected on its next hop anyway).
pub(crate) fn csrf_token(
    state: &crate::state::AppState,
    jar: &axum_extra::extract::PrivateCookieJar,
    user: &crate::auth::CurrentUser,
) -> Option<String> {
    let lease = jar.get(crate::state::SESSION_COOKIE).and_then(|cookie| {
        state
            .sessions
            .lease(cookie.value(), std::time::Instant::now())
    })?;
    (lease.username == user.name).then_some(lease.csrf)
}

/// Administration is possible when the root broker is configured and the
/// session is known: the page then renders action forms, otherwise it stays
/// read-only with the notice.
pub(crate) struct Actions {
    csrf: Option<String>,
}

impl Actions {
    pub(crate) fn new(
        state: &crate::state::AppState,
        jar: &axum_extra::extract::PrivateCookieJar,
        user: &crate::auth::CurrentUser,
    ) -> Self {
        let csrf = if state.admin_socket.is_some() {
            csrf_token(state, jar, user)
        } else {
            None
        };
        Self { csrf }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.csrf.is_some()
    }

    /// A small form posting one operation to the confirmation step.
    pub(crate) fn button(&self, label: &str, action: &str, fields: &[(&str, &str)]) -> String {
        let Some(csrf) = &self.csrf else {
            return String::new();
        };
        let hidden: String = fields
            .iter()
            .map(|(name, value)| {
                format!(
                    r#"<input type="hidden" name="{name}" value="{}">"#,
                    html_escape(value)
                )
            })
            .collect();
        format!(
            r#"<form method="post" action="/administracao/confirmar"><input type="hidden" name="action" value="{action}"><input type="hidden" name="csrf" value="{}">{hidden}<button type="submit">{label}</button></form>"#,
            html_escape(csrf)
        )
    }

    /// The same, styled as a primary header action.
    pub(crate) fn primary(&self, label: &str, action: &str, fields: &[(&str, &str)]) -> String {
        self.button(label, action, fields).replace(
            "<button type=\"submit\">",
            "<button type=\"submit\" class=\"primary\">",
        )
    }

    /// A form with visible inputs (`inner` HTML) that posts one operation to
    /// the confirmation step; used for parameters the user types.
    pub(crate) fn inline_form(&self, label: &str, action: &str, inner: &str) -> String {
        let Some(csrf) = &self.csrf else {
            return String::new();
        };
        format!(
            r#"<form class="inline-form" method="post" action="/administracao/confirmar"><input type="hidden" name="action" value="{action}"><input type="hidden" name="csrf" value="{}">{inner}<button type="submit">{label}</button></form>"#,
            html_escape(csrf)
        )
    }

    pub(crate) fn notice(&self) -> String {
        if self.enabled() {
            String::new()
        } else {
            ADMINISTRATION_UNAVAILABLE_NOTICE.to_owned()
        }
    }
}

pub(crate) fn render_with(
    title: &str,
    active_href: &str,
    user: &crate::auth::CurrentUser,
    subtitle: &str,
    actions: &str,
    body: String,
) -> axum::response::Html<String> {
    axum::response::Html(layout::page_with(
        title,
        active_href,
        user,
        subtitle,
        actions,
        &body,
    ))
}

pub(crate) fn render(
    title: &str,
    active_href: &str,
    user: &crate::auth::CurrentUser,
    body: String,
) -> axum::response::Html<String> {
    axum::response::Html(layout::page(title, active_href, user, &body))
}

pub(crate) fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
