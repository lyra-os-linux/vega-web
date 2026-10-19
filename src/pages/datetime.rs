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
                icon_stat("datetime", "Fuso horário", &html_escape(&status.timezone)),
                icon_stat(
                    if status.ntp { "check" } else { "warning" },
                    "NTP",
                    &format!(
                        r#"<span class="badge {}">{}</span>"#,
                        if status.ntp { "on" } else { "off" },
                        if status.ntp { "ativo" } else { "inativo" },
                    )
                ),
                icon_stat("users", "Locale", &html_escape(&status.locale)),
                icon_stat("hardware", "Teclado", &html_escape(&status.keymap)),
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
                    r#"<label>Fuso horário<select name="timezone">{options}</select></label>
<label>Sincronização automática (NTP)<select name="ntp"><option value="true"{}>Ativada</option><option value="false"{}>Desativada</option></select></label>"#,
                    if status.ntp { " selected" } else { "" },
                    if status.ntp { "" } else { " selected" },
                );
                format!(
                    "<h3>Alterar</h3>{}",
                    actions.inline_form("Aplicar", "datetime", &inner)
                )
            } else {
                actions.notice()
            };
            format!("{cards}{form}")
        }
        Err(error) => error_body("Status de data/hora indisponível", error),
    };
    render_with("Data e Hora", "/data-hora", &user, "", "", body)
}
