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
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
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
            icon_stat(
                "services",
                t("Unidades", "Units", "Unidades"),
                &units.len().to_string()
            ),
            icon_stat(
                "logs",
                t(
                    "Limite por consulta",
                    "Limit per query",
                    "Límite por consulta"
                ),
                &MAX_LINES.to_string()
            ),
        ));
    }

    let example = t("ex.:", "e.g.", "p. ej.");
    body.push_str(&format!(
        r#"<form method="get" action="/logs">
<label>{}<br>
<select name="unit"><option value="">{}</option>{unit_options}</select>
</label>
<label>{}<br><input type="text" name="priority" value="{}" placeholder="{} err"></label>
<label>{}<br><input type="text" name="since" value="{}" placeholder="{} -1h"></label>
<label>{}<br><input type="text" name="search" value="{}"></label>
<button type="submit">{}</button>
</form>"#,
        t("Unidade", "Unit", "Unidad"),
        t("selecione…", "select…", "seleccione…"),
        t("Prioridade", "Priority", "Prioridad"),
        html_escape(&query.priority),
        example,
        t("Desde", "Since", "Desde"),
        html_escape(&query.since),
        example,
        t("Busca", "Search", "Búsqueda"),
        html_escape(&query.search),
        t("Consultar", "Query", "Consultar"),
    ));

    if let Err(error) = &units {
        if actions.enabled() {
            body.push_str(&actions.unlock(
                ReadQuery::LogUnits,
                t("Lista de unidades", "Unit list", "Lista de unidades"),
            ));
        }
        body.push_str(&error_body(
            lang,
            t(
                "Lista de unidades indisponível",
                "Unit list unavailable",
                "Lista de unidades no disponible",
            ),
            error,
        ));
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
            Err(error) => body.push_str(&error_body(
                lang,
                t(
                    "Consulta de log indisponível",
                    "Log query unavailable",
                    "Consulta de registro no disponible",
                ),
                error,
            )),
        }
    }

    render("Logs", "/logs", &user, body)
}
