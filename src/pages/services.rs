use axum::extract::{Extension, Query, State};
use axum::response::Html;
use lyra_vega_dbus::ServicesClient;
use serde::Deserialize;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{error_body, html_escape, render};

#[derive(Default, Deserialize)]
pub struct ServicesQuery {
    #[serde(default)]
    all: bool,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<ServicesQuery>,
) -> Html<String> {
    let client = state.dbus.services();
    let result = if query.all {
        client.list_all().await
    } else {
        client.list().await
    };
    let body = match result {
        Ok(mut services) => {
            services.sort_by(|a, b| a.label.cmp(&b.label));
            let active = services.iter().filter(|service| service.active).count();
            let enabled = services.iter().filter(|service| service.enabled).count();
            let rows: String = services
                .iter()
                .map(|service| {
                    format!(
                        r#"<tr>
<td>{}<br><small>{}</small></td>
<td><span class="badge {}">{}</span></td>
<td><span class="badge {}">{}</span></td>
</tr>"#,
                        html_escape(&service.label),
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
            format!(
                r#"<div class="cards">{} {} {}</div>
<p>Somente leitura nesta versão — ligar/desligar serviços chega numa fase seguinte.</p>
<div class="section-actions"><h3>{}</h3><a class="button-link" href="{}">{}</a></div>
<table>
<thead><tr><th>Serviço</th><th>Inicialização</th><th>Estado atual</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                icon_stat("services", "Serviços", &services.len().to_string()),
                icon_stat("check", "Ativos", &active.to_string()),
                icon_stat("software", "Habilitados", &enabled.to_string()),
                if query.all {
                    "Todos os serviços"
                } else {
                    "Serviços principais"
                },
                if query.all {
                    "/servicos"
                } else {
                    "/servicos?all=true"
                },
                if query.all {
                    "Ver principais"
                } else {
                    "Ver todos"
                },
            )
        }
        Err(error) => error_body("Lista de serviços indisponível", error),
    };

    render("Serviços", "/servicos", &user.0, body)
}
