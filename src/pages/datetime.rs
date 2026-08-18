use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::DateTimeClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let body = match state.dbus.datetime().status().await {
        Ok(status) => format!(
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
        ),
        Err(error) => error_body("Status de data/hora indisponível", error),
    };

    render("Data e Hora", "/data-hora", &user.0, body)
}
