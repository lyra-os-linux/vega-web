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
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let actions = Actions::new(&state, &jar, &user);
    let client = state.dbus.software();
    let mut body = actions.notice();
    let mut subtitle = String::new();
    let mut header = String::new();

    match client.package_manager_name().await {
        Ok(name) => {
            subtitle = format!(
                "{}: {}",
                t(
                    "Gerenciador de pacotes",
                    "Package manager",
                    "Gestor de paquetes"
                ),
                html_escape(&name)
            )
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Gerenciador de pacotes indisponível",
                "Package manager unavailable",
                "Gestor de paquetes no disponible",
            ),
            error,
        )),
    }

    body.push_str(&format!(
        r#"<form method="get" action="/software" class="inline-form">
<label>{}<input type="search" name="q" value="{}" placeholder="{}"></label>
<button type="submit">{}</button>
</form>"#,
        t("Buscar pacotes", "Search packages", "Buscar paquetes"),
        html_escape(&query.q),
        t("nome do pacote", "package name", "nombre del paquete"),
        t("Buscar", "Search", "Buscar"),
    ));
    if !query.q.trim().is_empty() {
        match client.search_native(query.q.trim()).await {
            Ok(results) => body.push_str(&package_table(
                t(
                    "Resultados da busca",
                    "Search results",
                    "Resultados de la búsqueda",
                ),
                &results,
                &actions,
                true,
            )),
            Err(error) => body.push_str(&error_body(
                lang,
                t(
                    "Busca indisponível",
                    "Search unavailable",
                    "Búsqueda no disponible",
                ),
                error,
            )),
        }
    }
    match client.list_native_updates().await {
        Ok(updates) => {
            if !updates.is_empty() {
                header.push_str(&actions.primary(
                    &format!(
                        "{} {} {}",
                        t("Aplicar", "Apply", "Aplicar"),
                        updates.len(),
                        t("atualização(ões)", "update(s)", "actualización(es)"),
                    ),
                    "update-all",
                    &[],
                ));
            }
            body.push_str(&package_table(
                t(
                    "Atualizações disponíveis",
                    "Available updates",
                    "Actualizaciones disponibles",
                ),
                &updates,
                &actions,
                false,
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Lista de atualizações indisponível",
                "Update list unavailable",
                "Lista de actualizaciones no disponible",
            ),
            error,
        )),
    }
    header.push_str(&actions.button(
        t("Limpar cache", "Clear cache", "Limpiar caché"),
        "clear-cache",
        &[],
    ));
    match client.list_repos().await {
        Ok(mut repos) => {
            repos.sort_by(|a, b| a.name.cmp(&b.name));
            let rows: String = repos
                .iter()
                .map(|repo| {
                    let toggle = if repo.enabled {
                        actions.button(
                            t("Desabilitar", "Disable", "Deshabilitar"),
                            "repo-enabled",
                            &[("name", &repo.name), ("enabled", "false")],
                        )
                    } else {
                        actions.button(
                            t("Habilitar", "Enable", "Habilitar"),
                            "repo-enabled",
                            &[("name", &repo.name), ("enabled", "true")],
                        )
                    };
                    format!(
                        r#"<tr><td>{}</td><td><span class="badge {}">{}</span></td><td><div class="row-actions">{toggle}</div></td></tr>"#,
                        html_escape(&repo.name),
                        if repo.enabled { "on" } else { "off" },
                        if repo.enabled {
                            t("habilitado", "enabled", "habilitado")
                        } else {
                            t("desabilitado", "disabled", "deshabilitado")
                        },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<h3>{}</h3>
<table><thead><tr><th>{}</th><th>{}</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#,
                t("Repositórios", "Repositories", "Repositorios"),
                t("Nome", "Name", "Nombre"),
                t("Estado", "State", "Estado"),
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Lista de repositórios indisponível",
                "Repository list unavailable",
                "Lista de repositorios no disponible",
            ),
            error,
        )),
    }
    render_with("Software", "/software", &user, &subtitle, &header, body)
}

fn package_table(
    title: &str,
    packages: &[lyra_vega_dbus::PackageRef],
    actions: &Actions,
    allow_install: bool,
) -> String {
    let lang = actions.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    if packages.is_empty() {
        return format!(
            r#"<h3>{title}</h3><p class="empty">{}</p>"#,
            t("Nada aqui.", "Nothing here.", "Nada aquí.")
        );
    }
    let rows: String = packages
        .iter()
        .map(|package| {
            let status = if package.installed {
                format!(
                    r#"<span class="badge on">{}</span>"#,
                    t("instalado", "installed", "instalado")
                )
            } else {
                format!(
                    r#"<span class="badge">{}</span>"#,
                    t("disponível", "available", "disponible")
                )
            };
            let action = if package.installed {
                actions.button(t("Remover", "Remove", "Quitar"), "remove", &[("package", &package.name)])
            } else if allow_install {
                actions.button(t("Instalar", "Install", "Instalar"), "install", &[("package", &package.name)])
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
<table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#,
        t("Pacote", "Package", "Paquete"),
        t("Repositório", "Repository", "Repositorio"),
        t("Estado", "State", "Estado"),
    )
}
