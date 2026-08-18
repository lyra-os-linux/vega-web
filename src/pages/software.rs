use axum::Form;
use axum::extract::{Extension, Query, State};
use axum::response::{Html, Redirect};
use lyra_vega_dbus::SoftwareClient;
use serde::Deserialize;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{error_body, html_escape, render};

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    install: String,
    #[serde(default)]
    tx: Option<u32>,
}

#[derive(Deserialize)]
pub struct InstallForm {
    package: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<SearchQuery>,
) -> Html<String> {
    let client = state.dbus.software();
    let mut body = String::new();

    match query.install.as_str() {
        "started" => body.push_str(&format!(
            r#"<p class="notice success">Instalação iniciada pelo Zypper (transação #{}). Ela continuará em segundo plano.</p>"#,
            query.tx.unwrap_or_default()
        )),
        "invalid" => body.push_str(
            r#"<p class="error" role="alert">O identificador do pacote é inválido.</p>"#,
        ),
        "error" => body.push_str(r#"<p class="error" role="alert">Não foi possível iniciar a instalação. Verifique a autorização e tente novamente.</p>"#),
        _ => {}
    }

    match client.package_manager_name().await {
        Ok(name) => body.push_str(&format!(
            r#"<div class="cards">{}</div>"#,
            icon_stat("software", "Gerenciador de pacotes", &html_escape(&name))
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
        match client.search_native(query.q.trim()).await {
            Ok(results) => body.push_str(&package_table("Resultados da busca", &results)),
            Err(error) => body.push_str(&error_body("Busca indisponível", error)),
        }
    }

    match client.list_native_updates().await {
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
            let action = if package.installed {
                r#"<span class="badge on">instalado</span>"#.to_string()
            } else {
                format!(
                    r#"<form class="row-action-form" method="post" action="/software"><input type="hidden" name="package" value="{}"><button type="submit">Instalar</button></form>"#,
                    html_escape(&package.id)
                )
            };
            format!(
                "<tr><td>{}<br><small>{}</small></td><td>{}</td><td>{}</td><td>{action}</td></tr>",
                html_escape(&package.name),
                html_escape(&package.description),
                "Zypper",
                html_escape(&package.repository),
            )
        })
        .collect();
    format!(
        r#"<h3>{title}</h3>
<table><thead><tr><th>Pacote</th><th>Origem</th><th>Repositório</th><th>Ação</th></tr></thead><tbody>{rows}</tbody></table>"#
    )
}

pub async fn install_native(
    State(state): State<AppState>,
    Extension(_user): Extension<CurrentUser>,
    Form(form): Form<InstallForm>,
) -> Redirect {
    let package = form.package.trim();
    if !valid_native_package_id(package) {
        return Redirect::to("/software?install=invalid");
    }

    // The web frontend deliberately supports the native backend only. Never
    // accept an origin from the request: forcing `official` keeps Flatpak and
    // any future provider outside this surface.
    match state.dbus.software().install("official", package).await {
        Ok(transaction_id) => {
            Redirect::to(&format!("/software?install=started&tx={transaction_id}"))
        }
        Err(error) => {
            eprintln!("vega-web: falha ao instalar pacote Zypper {package}: {error}");
            Redirect::to("/software?install=error")
        }
    }
}

fn valid_native_package_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-+._:".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::valid_native_package_id;

    #[test]
    fn native_package_ids_reject_request_manipulation() {
        assert!(valid_native_package_id("patterns-base-base"));
        assert!(valid_native_package_id("libQt6Core6-6.8.2"));
        assert!(!valid_native_package_id(""));
        assert!(!valid_native_package_id("pkg --root /tmp"));
        assert!(!valid_native_package_id("pkg/../../etc"));
    }
}
