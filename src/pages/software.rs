use axum::extract::{Extension, Query, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::SoftwareClient;
use serde::Deserialize;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{Actions, error_body, html_escape, render_with};

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
}

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<SearchQuery>,
) -> Html<String> {
    let actions = Actions::new(&state, &jar, &user);
    let client = state.dbus.software();
    let mut body = actions.notice();
    let mut subtitle = String::new();
    let mut header = String::new();

    match client.package_manager_name().await {
        Ok(name) => subtitle = format!("Gerenciador de pacotes: {}", html_escape(&name)),
        Err(error) => body.push_str(&error_body("Gerenciador de pacotes indisponível", error)),
    }

    body.push_str(&format!(
        r#"<form method="get" action="/software" class="inline-form">
<label>Buscar pacotes<input type="search" name="q" value="{}" placeholder="nome do pacote"></label>
<button type="submit">Buscar</button>
</form>"#,
        html_escape(&query.q)
    ));
    if !query.q.trim().is_empty() {
        match client.search_native(query.q.trim()).await {
            Ok(results) => body.push_str(&package_table(
                "Resultados da busca",
                &results,
                &actions,
                true,
            )),
            Err(error) => body.push_str(&error_body("Busca indisponível", error)),
        }
    }
    match client.list_native_updates().await {
        Ok(updates) => {
            if !updates.is_empty() {
                header.push_str(&actions.primary(
                    &format!("Aplicar {} atualização(ões)", updates.len()),
                    "update-all",
                    &[],
                ));
            }
            body.push_str(&package_table(
                "Atualizações disponíveis",
                &updates,
                &actions,
                false,
            ));
        }
        Err(error) => body.push_str(&error_body("Lista de atualizações indisponível", error)),
    }
    header.push_str(&actions.button("Limpar cache", "clear-cache", &[]));
    match client.list_repos().await {
        Ok(mut repos) => {
            repos.sort_by(|a, b| a.name.cmp(&b.name));
            let rows: String = repos
                .iter()
                .map(|repo| {
                    let toggle = if repo.enabled {
                        actions.button(
                            "Desabilitar",
                            "repo-enabled",
                            &[("name", &repo.name), ("enabled", "false")],
                        )
                    } else {
                        actions.button(
                            "Habilitar",
                            "repo-enabled",
                            &[("name", &repo.name), ("enabled", "true")],
                        )
                    };
                    format!(
                        r#"<tr><td>{}</td><td><span class="badge {}">{}</span></td><td><div class="row-actions">{toggle}</div></td></tr>"#,
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
<table><thead><tr><th>Nome</th><th>Estado</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Err(error) => body.push_str(&error_body("Lista de repositórios indisponível", error)),
    }
    render_with("Software", "/software", &user, &subtitle, &header, body)
}

fn package_table(
    title: &str,
    packages: &[lyra_vega_dbus::PackageRef],
    actions: &Actions,
    allow_install: bool,
) -> String {
    if packages.is_empty() {
        return format!(r#"<h3>{title}</h3><p class="empty">Nada aqui.</p>"#);
    }
    let rows: String = packages
        .iter()
        .map(|package| {
            let status = if package.installed {
                r#"<span class="badge on">instalado</span>"#
            } else {
                r#"<span class="badge">disponível</span>"#
            };
            let action = if package.installed {
                actions.button("Remover", "remove", &[("package", &package.name)])
            } else if allow_install {
                actions.button("Instalar", "install", &[("package", &package.name)])
            } else {
                String::new()
            };
            format!(
                r#"<tr><td>{}<small>{}</small></td><td>{}</td><td>{status}</td><td><div class="row-actions">{action}</div></td></tr>"#,
                html_escape(&package.name),
                html_escape(&package.description),
                html_escape(&package.repository),
            )
        })
        .collect();
    format!(
        r#"<h3>{title}</h3>
<table><thead><tr><th>Pacote</th><th>Repositório</th><th>Estado</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#
    )
}
