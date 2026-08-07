use axum::extract::{Extension, Query, State};
use axum::response::Html;
use lyra_vega_dbus::SoftwareClient;
use serde::Deserialize;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<SearchQuery>,
) -> Html<String> {
    let client = state.dbus.software();
    let mut body = String::new();

    match client.package_manager_name().await {
        Ok(name) => body.push_str(&format!(
            r#"<div class="cards"><div class="card">Gerenciador de pacotes<strong>{}</strong></div></div>"#,
            html_escape(&name)
        )),
        Err(error) => body.push_str(&error_body("Gerenciador de pacotes indisponível", error)),
    }

    body.push_str(&format!(
        r#"<form method="get" action="/software">
<label>Buscar pacotes<br><input type="text" name="q" value="{}" placeholder="nome do pacote"></label>
<button type="submit">Buscar</button>
</form>"#,
        html_escape(&query.q)
    ));

    if !query.q.trim().is_empty() {
        match client.search(query.q.trim()).await {
            Ok(results) => body.push_str(&package_table("Resultados da busca", &results)),
            Err(error) => body.push_str(&error_body("Busca indisponível", error)),
        }
    }

    match client.list_updates().await {
        Ok(updates) => body.push_str(&package_table("Atualizações disponíveis", &updates)),
        Err(error) => body.push_str(&error_body("Lista de atualizações indisponível", error)),
    }

    match client.list_repos().await {
        Ok(mut repos) => {
            repos.sort_by(|a, b| a.name.cmp(&b.name));
            let rows: String = repos
                .iter()
                .map(|repo| {
                    format!(
                        "<tr><td>{}</td><td><span class=\"badge {}\">{}</span></td></tr>",
                        html_escape(&repo.name),
                        if repo.enabled { "on" } else { "off" },
                        if repo.enabled {
                            "habilitado"
                        } else {
                            "desabilitado"
                        },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<h3>Repositórios</h3>
<table><thead><tr><th>Nome</th><th>Estado</th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Err(error) => body.push_str(&error_body("Lista de repositórios indisponível", error)),
    }

    render("Software", "/software", &user.0, body)
}

fn package_table(title: &str, packages: &[lyra_vega_dbus::PackageRef]) -> String {
    if packages.is_empty() {
        return format!("<h3>{title}</h3><p>Nada aqui.</p>");
    }
    let rows: String = packages
        .iter()
        .map(|package| {
            format!(
                "<tr><td>{}<br><small>{}</small></td><td>{}</td><td>{}</td></tr>",
                html_escape(&package.name),
                html_escape(&package.description),
                html_escape(&package.origin),
                html_escape(&package.repository),
            )
        })
        .collect();
    format!(
        r#"<h3>{title}</h3>
<table><thead><tr><th>Pacote</th><th>Origem</th><th>Repositório</th></tr></thead><tbody>{rows}</tbody></table>"#
    )
}
