use axum::extract::{Extension, Query, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::LogsClient;
use serde::Deserialize;
use vega_web::admin_read::{LogUnits, ReadQuery};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{Actions, cached_read, error_body, html_escape, render};

const MAX_LINES: u32 = 200;

#[derive(Deserialize, Default)]
pub struct LogsQuery {
    #[serde(default)]
    unit: String,
    #[serde(default)]
    priority: String,
    #[serde(default)]
    since: String,
    #[serde(default)]
    search: String,
}

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<LogsQuery>,
) -> Html<String> {
    let actions = Actions::new(&state, &jar, &user);
    let client = state.dbus.logs();
    let mut body = String::new();

    let units = match cached_read::<LogUnits>(&state, &jar, ReadQuery::LogUnits) {
        Some(payload) => Ok(payload.units),
        None => client.list_units().await.map_err(|error| error.to_string()),
    };
    let unit_options: String = match &units {
        Ok(units) => units
            .iter()
            .map(|unit| {
                let selected = if unit == &query.unit { " selected" } else { "" };
                format!(
                    r#"<option value="{0}"{selected}>{0}</option>"#,
                    html_escape(unit)
                )
            })
            .collect(),
        Err(_) => String::new(),
    };

    if let Ok(units) = &units {
        body.push_str(&format!(
            r#"<div class="cards">{} {}</div>"#,
            icon_stat("services", "Unidades", &units.len().to_string()),
            icon_stat("logs", "Limite por consulta", &MAX_LINES.to_string()),
        ));
    }

    body.push_str(&format!(
        r#"<form method="get" action="/logs">
<label>Unidade<br>
<select name="unit"><option value="">selecione…</option>{unit_options}</select>
</label>
<label>Prioridade<br><input type="text" name="priority" value="{}" placeholder="ex.: err"></label>
<label>Desde<br><input type="text" name="since" value="{}" placeholder="ex.: -1h"></label>
<label>Busca<br><input type="text" name="search" value="{}"></label>
<button type="submit">Consultar</button>
</form>"#,
        html_escape(&query.priority),
        html_escape(&query.since),
        html_escape(&query.search),
    ));

    if let Err(error) = &units {
        if actions.enabled() {
            body.push_str(&actions.unlock(ReadQuery::LogUnits, "Lista de unidades"));
        }
        body.push_str(&error_body("Lista de unidades indisponível", error));
    }

    if !query.unit.trim().is_empty() {
        match client
            .query(
                &query.unit,
                &query.priority,
                &query.since,
                &query.search,
                MAX_LINES,
            )
            .await
        {
            Ok(lines) => {
                let text = lines
                    .iter()
                    .map(|line| html_escape(line))
                    .collect::<Vec<_>>()
                    .join("\n");
                body.push_str(&format!(
                    "<pre style=\"white-space: pre-wrap; font-size: 0.85rem;\">{text}</pre>"
                ));
            }
            Err(error) => body.push_str(&error_body("Consulta de log indisponível", error)),
        }
    }

    render("Logs", "/logs", &user, body)
}
