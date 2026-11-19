pub mod admin;
pub mod backup;
pub mod dashboard;
pub mod datetime;
pub mod diagnostics;
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

pub(crate) const ADMINISTRATION_UNAVAILABLE_NOTICE: &str = r#"<p class="notice">As alterações pelo painel estão desativadas nesta instalação: o broker administrativo (vega-web-admin.socket) não está configurado. Use o Vega na sessão local ou pelo terminal.</p>"#;

/// The notice above, in the session's language.
pub(crate) fn unavailable_notice(lang: vega_web::lang::Lang) -> String {
    match lang {
        vega_web::lang::Lang::Pt => ADMINISTRATION_UNAVAILABLE_NOTICE.to_owned(),
        _ => format!(
            r#"<p class="notice">{}</p>"#,
            lang.text(
                "",
                "Changes from the panel are disabled on this installation: the administrative broker (vega-web-admin.socket) is not configured. Use Vega in the local session or from the terminal.",
                "Los cambios desde el panel están desactivados en esta instalación: el broker administrativo (vega-web-admin.socket) no está configurado. Use Vega en la sesión local o desde la terminal.",
            )
        ),
    }
}

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
            user.lang.text(
                "Ação indisponível",
                "Action unavailable",
                "Acción no disponible",
            ),
            uri.path(),
            &user,
            unavailable_notice(user.lang),
        ),
    )
}

/// A failed query, in human terms. The raw daemon error stays available in a
/// collapsed detail block instead of being the message itself.
pub(crate) fn error_body(
    lang: vega_web::lang::Lang,
    context: &str,
    detail: impl std::fmt::Display,
) -> String {
    let t = |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let raw = detail.to_string();
    let lower = raw.to_lowercase();
    let (level, explanation) = if lower.contains("authorizationfailed")
        || lower.contains("not authorized")
        || lower.contains("notauthorized")
    {
        (
            "warn",
            t(
                "Esta consulta exige autorização de administrador, que o painel ainda não repassa para leituras. Use o console (vega) ou o terminal web.",
                "This query requires administrator authorization, which the panel does not yet pass on for reads. Use the console (vega) or the web terminal.",
                "Esta consulta requiere autorización de administrador, que el panel todavía no transmite para lecturas. Use la consola (vega) o la terminal web.",
            ),
        )
    } else if lower.contains("capabilityunavailable") || lower.contains("not supported") {
        (
            "info",
            t(
                "Recurso não disponível nesta edição.",
                "Feature not available in this edition.",
                "Función no disponible en esta edición.",
            ),
        )
    } else if lower.contains("snapper") {
        (
            "info",
            t(
                "Snapshots exigem Btrfs com Snapper; esta instalação usa outro sistema de arquivos.",
                "Snapshots require Btrfs with Snapper; this installation uses another file system.",
                "Las instantáneas requieren Btrfs con Snapper; esta instalación usa otro sistema de archivos.",
            ),
        )
    } else if lower.contains("not activatable") || lower.contains("was not provided by any") {
        (
            "error",
            t(
                "O serviço vegad não está disponível. Verifique se vegad.service está instalado e ativo.",
                "The vegad service is not available. Check that vegad.service is installed and active.",
                "El servicio vegad no está disponible. Compruebe que vegad.service esté instalado y activo.",
            ),
        )
    } else if lower.contains("timed out") || lower.contains("did not receive a reply") {
        (
            "warn",
            t(
                "O vegad não respondeu a tempo. Tente de novo em instantes.",
                "vegad did not answer in time. Try again in a moment.",
                "vegad no respondió a tiempo. Inténtelo de nuevo en unos instantes.",
            ),
        )
    } else {
        (
            "error",
            t(
                "A consulta falhou.",
                "The query failed.",
                "La consulta falló.",
            ),
        )
    };
    format!(
        r#"<div class="notice {level}"><strong>{context}</strong><span>{explanation}</span><details><summary>{}</summary><code>{}</code></details></div>"#,
        t(
            "Detalhes técnicos",
            "Technical details",
            "Detalles técnicos"
        ),
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
    lang: vega_web::lang::Lang,
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
        Self {
            csrf,
            lang: user.lang,
        }
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
            unavailable_notice(self.lang)
        }
    }
}

/// How long an administrative read stays valid in the session.
pub(crate) const READ_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(300);

/// A read fetched through the broker for this session, if still fresh.
pub(crate) fn cached_read<T: serde::de::DeserializeOwned>(
    state: &crate::state::AppState,
    jar: &axum_extra::extract::PrivateCookieJar,
    query: vega_web::admin_read::ReadQuery,
) -> Option<T> {
    let cookie = jar.get(crate::state::SESSION_COOKIE)?;
    let json = state
        .sessions
        .cached_read(cookie.value(), query.key(), READ_MAX_AGE)?;
    serde_json::from_str(&json).ok()
}

impl Actions {
    /// The notice offering to fetch an administrative read with the user's
    /// password, or the plain explanation when the broker is not configured.
    pub(crate) fn unlock(&self, query: vega_web::admin_read::ReadQuery, context: &str) -> String {
        let t = |pt: &'static str, en: &'static str, es: &'static str| self.lang.text(pt, en, es);
        let button = self.button(
            t(
                "Desbloquear com senha",
                "Unlock with password",
                "Desbloquear con contraseña",
            ),
            &format!("read-{}", query.key()),
            &[],
        );
        if button.is_empty() {
            return format!(
                r#"<div class="notice warn"><strong>{context}</strong><span>{}</span></div>"#,
                t(
                    "Esta leitura exige autorização de administrador e o broker administrativo não está configurado nesta instalação.",
                    "This read requires administrator authorization and the administrative broker is not configured on this installation.",
                    "Esta lectura requiere autorización de administrador y el broker administrativo no está configurado en esta instalación.",
                )
            );
        }
        format!(
            r#"<div class="notice"><strong>{context}</strong><span>{}</span>{button}</div>"#,
            t(
                "Esta leitura exige autorização de administrador. Confirme com sua senha para lê-la com a sua identidade; o resultado fica disponível por cinco minutos.",
                "This read requires administrator authorization. Confirm with your password to read it with your identity; the result stays available for five minutes.",
                "Esta lectura requiere autorización de administrador. Confirme con su contraseña para leerla con su identidad; el resultado queda disponible durante cinco minutos.",
            )
        )
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

#[cfg(test)]
mod tests {
    use vega_web::lang::Lang;

    #[test]
    fn error_body_follows_the_session_language() {
        let english = super::error_body(Lang::En, "Users", "timed out");
        assert!(english.contains("vegad did not answer in time"));
        assert!(english.contains("Technical details"));
        let spanish = super::error_body(Lang::Es, "Usuarios", "boom");
        assert!(spanish.contains("La consulta falló."));
        let portuguese = super::error_body(Lang::Pt, "Usuários", "boom");
        assert!(portuguese.contains("A consulta falhou."));
    }

    #[test]
    fn unavailable_notice_keeps_the_portuguese_constant() {
        assert_eq!(
            super::unavailable_notice(Lang::Pt),
            super::ADMINISTRATION_UNAVAILABLE_NOTICE
        );
        assert!(super::unavailable_notice(Lang::En).contains("administrative broker"));
    }
}
