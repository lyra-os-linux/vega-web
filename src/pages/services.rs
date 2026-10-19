use axum::extract::{Extension, Query, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::ServicesClient;
use serde::Deserialize;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{Actions, error_body, html_escape, render_with};

#[derive(Default, Deserialize)]
pub struct ServicesQuery {
    #[serde(default)]
    all: bool,
    #[serde(default)]
    q: String,
}

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<ServicesQuery>,
) -> Html<String> {
    let actions = Actions::new(&state, &jar, &user);
    let client = state.dbus.services();
    let result = if query.all {
        client.list_all().await
    } else {
        client.list().await
    };
    let filter = query.q.trim().to_lowercase();
    let (subtitle, body) = match result {
        Ok(mut services) => {
            services.sort_by(|a, b| a.label.cmp(&b.label));
            let total = services.len();
            let active = services.iter().filter(|service| service.active).count();
            let enabled = services.iter().filter(|service| service.enabled).count();
            let shown: Vec<_> = services
                .iter()
                .filter(|service| {
                    filter.is_empty()
                        || service.label.to_lowercase().contains(&filter)
                        || service.name.to_lowercase().contains(&filter)
                })
                .collect();
            let rows: String = shown
                .iter()
                .map(|service| {
                    let dot = if service.active { "" } else { "off" };
                    let buttons = if actions.enabled() && service.available {
                        format!(
                            r#"<div class="row-actions">{}{}{}</div>"#,
                            actions.button("Reiniciar", "service-restart", &[("name", &service.name)]),
                            if service.active {
                                actions.button(
                                    "Parar",
                                    "service-running",
                                    &[("name", &service.name), ("enabled", "false")],
                                )
                            } else {
                                actions.button(
                                    "Iniciar",
                                    "service-running",
                                    &[("name", &service.name), ("enabled", "true")],
                                )
                            },
                            if service.enabled {
                                actions.button(
                                    "Desabilitar",
                                    "service-enabled",
                                    &[("name", &service.name), ("enabled", "false")],
                                )
                            } else {
                                actions.button(
                                    "Habilitar",
                                    "service-enabled",
                                    &[("name", &service.name), ("enabled", "true")],
                                )
                            },
                        )
                    } else {
                        String::new()
                    };
                    format!(
                        r#"<tr>
<td><span class="k"><span class="dot {dot}" aria-hidden="true"></span><span>{}<small>{} · {}</small></span></span></td>
<td><span class="badge {}">{}</span></td>
<td><span class="badge {}">{}</span></td>
<td>{buttons}</td>
</tr>"#,
                        html_escape(&service.label),
                        html_escape(&service.name),
                        html_escape(&service.description),
                        if service.enabled { "on" } else { "off" },
                        if service.enabled {
                            "habilitado"
                        } else {
                            "desabilitado"
                        },
                        if service.active { "on" } else { "off" },
                        if service.active { "ativo" } else { "inativo" },
                    )
                })
                .collect();
            let table = if shown.is_empty() {
                r#"<p class="empty">Nenhum serviço corresponde à busca.</p>"#.to_owned()
            } else {
                format!(
                    r#"<table>
<thead><tr><th>Serviço</th><th>Inicialização</th><th>Estado</th><th></th></tr></thead>
<tbody>{rows}</tbody>
</table>"#
                )
            };
            let foot = if actions.enabled() {
                r#"<p class="tile-foot">Cada ação pede sua senha e é executada com a sua identidade; o resultado fica registrado na atividade e no journal.</p>"#
            } else {
                ""
            };
            (
                format!(
                    "{total} serviço(s) {} · {active} ativos · {enabled} habilitados na inicialização",
                    if query.all { "no total" } else { "principais" }
                ),
                format!("{}{table}{foot}", actions.notice()),
            )
        }
        Err(error) => (
            String::new(),
            error_body("Lista de serviços indisponível", error),
        ),
    };
    let header = format!(
        r#"<form method="get" action="/servicos"><input type="hidden" name="all" value="{all}"><input type="search" name="q" value="{q}" placeholder="Buscar serviço" aria-label="Buscar serviço"></form><a class="button" href="{href}">{label}</a>"#,
        all = query.all,
        q = html_escape(&query.q),
        href = if query.all {
            "/servicos"
        } else {
            "/servicos?all=true"
        },
        label = if query.all {
            "Ver principais"
        } else {
            "Ver todos"
        },
    );
    render_with("Serviços", "/servicos", &user, &subtitle, &header, body)
}
