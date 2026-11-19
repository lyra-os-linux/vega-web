use axum::extract::{Extension, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::DateTimeClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{Actions, error_body, html_escape, render_with};

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let actions = Actions::new(&state, &jar, &user);
    let client = state.dbus.datetime();
    let body = match client.status().await {
        Ok(status) => {
            let cards = format!(
                r#"<div class="cards">
{}
{}
{}
{}
</div>"#,
                icon_stat(
                    "datetime",
                    t("Fuso horário", "Time zone", "Zona horaria"),
                    &html_escape(&status.timezone)
                ),
                icon_stat(
                    if status.ntp { "check" } else { "warning" },
                    "NTP",
                    &format!(
                        r#"<span class="badge {}">{}</span>"#,
                        if status.ntp { "on" } else { "off" },
                        if status.ntp {
                            t("ativo", "active", "activo")
                        } else {
                            t("inativo", "inactive", "inactivo")
                        },
                    )
                ),
                icon_stat("users", "Locale", &html_escape(&status.locale)),
                icon_stat(
                    "hardware",
                    t("Teclado", "Keyboard", "Teclado"),
                    &html_escape(&status.keymap)
                ),
            );
            let form = if actions.enabled() {
                let timezones = client.list_timezones().await.unwrap_or_default();
                let options: String = timezones
                    .iter()
                    .map(|zone| {
                        format!(
                            r#"<option value="{0}"{1}>{0}</option>"#,
                            html_escape(zone),
                            if *zone == status.timezone {
                                " selected"
                            } else {
                                ""
                            }
                        )
                    })
                    .collect();
                let inner = format!(
                    r#"<label>{}<select name="timezone">{options}</select></label>
<label>{}<select name="ntp"><option value="true"{}>{}</option><option value="false"{}>{}</option></select></label>"#,
                    t("Fuso horário", "Time zone", "Zona horaria"),
                    t(
                        "Sincronização automática (NTP)",
                        "Automatic synchronization (NTP)",
                        "Sincronización automática (NTP)",
                    ),
                    if status.ntp { " selected" } else { "" },
                    t("Ativada", "Enabled", "Activada"),
                    if status.ntp { "" } else { " selected" },
                    t("Desativada", "Disabled", "Desactivada"),
                );
                format!(
                    "<h3>{}</h3>{}",
                    t("Alterar", "Change", "Cambiar"),
                    actions.inline_form(t("Aplicar", "Apply", "Aplicar"), "datetime", &inner)
                )
            } else {
                actions.notice()
            };
            format!("{cards}{form}")
        }
        Err(error) => error_body(
            lang,
            t(
                "Status de data/hora indisponível",
                "Date/time status unavailable",
                "Estado de fecha/hora no disponible",
            ),
            error,
        ),
    };
    render_with(
        t("Data e Hora", "Date and Time", "Fecha y Hora"),
        "/data-hora",
        &user,
        "",
        "",
        body,
    )
}
