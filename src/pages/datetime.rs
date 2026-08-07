use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::DateTimeClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let body = match state.dbus.datetime().status().await {
        Ok(status) => format!(
            r#"<div class="cards">
<div class="card">Fuso horário<strong>{}</strong></div>
<div class="card">NTP<strong><span class="badge {}">{}</span></strong></div>
<div class="card">Locale<strong>{}</strong></div>
<div class="card">Teclado<strong>{}</strong></div>
</div>"#,
            html_escape(&status.timezone),
            if status.ntp { "on" } else { "off" },
            if status.ntp { "ativo" } else { "inativo" },
            html_escape(&status.locale),
            html_escape(&status.keymap),
        ),
        Err(error) => error_body("Status de data/hora indisponível", error),
    };

    render("Data e Hora", "/data-hora", &user.0, body)
}
