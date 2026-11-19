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
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
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
                            actions.button(t("Reiniciar", "Restart", "Reiniciar"), "service-restart", &[("name", &service.name)]),
                            if service.active {
                                actions.button(
                                    t("Parar", "Stop", "Detener"),
                                    "service-running",
                                    &[("name", &service.name), ("enabled", "false")],
                                )
                            } else {
                                actions.button(
                                    t("Iniciar", "Start", "Iniciar"),
                                    "service-running",
                                    &[("name", &service.name), ("enabled", "true")],
                                )
                            },
                            if service.enabled {
                                actions.button(
                                    t("Desabilitar", "Disable", "Deshabilitar"),
                                    "service-enabled",
                                    &[("name", &service.name), ("enabled", "false")],
                                )
                            } else {
                                actions.button(
                                    t("Habilitar", "Enable", "Habilitar"),
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
                            t("habilitado", "enabled", "habilitado")
                        } else {
                            t("desabilitado", "disabled", "deshabilitado")
                        },
                        if service.active { "on" } else { "off" },
                        if service.active {
                            t("ativo", "active", "activo")
                        } else {
                            t("inativo", "inactive", "inactivo")
                        },
                    )
                })
                .collect();
            let table = if shown.is_empty() {
                format!(
                    r#"<p class="empty">{}</p>"#,
                    t(
                        "Nenhum serviço corresponde à busca.",
                        "No service matches the search.",
                        "Ningún servicio coincide con la búsqueda.",
                    )
                )
            } else {
                format!(
                    r#"<table>
<thead><tr><th>{}</th><th>{}</th><th>{}</th><th></th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                    t("Serviço", "Service", "Servicio"),
                    t("Inicialização", "Startup", "Inicio"),
                    t("Estado", "State", "Estado"),
                )
            };
            let foot = if actions.enabled() {
                format!(
                    r#"<p class="tile-foot">{}</p>"#,
                    t(
                        "Cada ação pede sua senha e é executada com a sua identidade; o resultado fica registrado na atividade e no journal.",
                        "Each action asks for your password and runs with your identity; the result is recorded in the activity log and in the journal.",
                        "Cada acción pide su contraseña y se ejecuta con su identidad; el resultado queda registrado en la actividad y en el journal.",
                    )
                )
            } else {
                String::new()
            };
            (
                format!(
                    "{total} {} {} · {active} {} · {enabled} {}",
                    t("serviço(s)", "service(s)", "servicio(s)"),
                    if query.all {
                        t("no total", "in total", "en total")
                    } else {
                        t("principais", "main", "principales")
                    },
                    t("ativos", "active", "activos"),
                    t(
                        "habilitados na inicialização",
                        "enabled at startup",
                        "habilitados al inicio",
                    ),
                ),
                format!("{}{table}{foot}", actions.notice()),
            )
        }
        Err(error) => (
            String::new(),
            error_body(
                lang,
                t(
                    "Lista de serviços indisponível",
                    "Service list unavailable",
                    "Lista de servicios no disponible",
                ),
                error,
            ),
        ),
    };
    let header = format!(
        r#"<form method="get" action="/servicos"><input type="hidden" name="all" value="{all}"><input type="search" name="q" value="{q}" placeholder="{search}" aria-label="{search}"></form><a class="button" href="{href}">{label}</a>"#,
        all = query.all,
        q = html_escape(&query.q),
        search = t("Buscar serviço", "Search service", "Buscar servicio"),
        href = if query.all {
            "/servicos"
        } else {
            "/servicos?all=true"
        },
        label = if query.all {
            t("Ver principais", "Show main", "Ver principales")
        } else {
            t("Ver todos", "Show all", "Ver todos")
        },
    );
    render_with(
        t("Serviços", "Services", "Servicios"),
        "/servicos",
        &user,
        &subtitle,
        &header,
        body,
    )
}
