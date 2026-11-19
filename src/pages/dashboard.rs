use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::{
    FirewallClient, MonitorClient, NetworkClient, ServicesClient, SoftwareClient, SystemClient,
};

use crate::auth::CurrentUser;
use crate::host;
use crate::state::AppState;

use super::{error_body, html_escape, render_with};
use vega_web::lang::Lang;

fn gigabytes(lang: Lang, bytes: u64) -> String {
    decimal(lang, format!("{:.1}", bytes as f64 / 1_073_741_824.0))
}

/// Comma decimals in Portuguese and Spanish, a point in English.
fn decimal(lang: Lang, value: String) -> String {
    if lang == Lang::En {
        value.replace(',', ".")
    } else {
        value.replace('.', ",")
    }
}

fn tile(label: &str, value: &str, bar: Option<f64>, foot: &str) -> String {
    let bar = bar
        .map(|percent| {
            let percent = percent.clamp(0.0, 100.0);
            let class = if percent >= 90.0 {
                "bar-danger"
            } else if percent >= 75.0 {
                "bar-warn"
            } else {
                "bar-accent"
            };
            format!(
                r#"<div class="bar-track"><div class="bar-value {class}" style="width: {percent:.0}%"></div></div>"#
            )
        })
        .unwrap_or_default();
    format!(
        r#"<div class="tile"><span class="tile-label">{label}</span><span class="tile-value">{value}</span>{bar}<span class="tile-foot">{foot}</span></div>"#
    )
}

fn kv(dot: &str, key: &str, value: &str) -> String {
    format!(
        r#"<div class="kv-row"><span class="k"><span class="dot {dot}" aria-hidden="true"></span>{key}</span><span class="v">{value}</span></div>"#
    )
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let machine = host::identity();
    let metrics = state.dbus.monitor().metrics().await;
    let disk = state.dbus.system().disk_usage().await;
    let services = state.dbus.services().list().await;
    let firewall = state.dbus.firewall().status().await;
    let interfaces = state.dbus.network().interfaces().await;
    // Every administrative login lands here. The daemon answers from its
    // bounded cache and starts one deduplicated refresh when that cache is
    // stale, so repository latency never blocks access to the overview.
    let updates = state.dbus.software().request_update_check().await;

    let mut body = String::new();
    let mut problems = String::new();

    // Row 1: resources.
    let mut tiles = String::new();
    match &metrics {
        Ok(m) => {
            tiles.push_str(&tile(
                &format!(
                    "CPU · {} {}",
                    host::cpu_count(),
                    t("núcleos", "cores", "núcleos")
                ),
                &format!("{:.0}<small>%</small>", m.cpu_percent),
                Some(m.cpu_percent),
                &format!(
                    "{} {}",
                    t("carga", "load", "carga"),
                    html_escape(&decimal(lang, host::load_average()))
                ),
            ));
            let mem_percent = if m.mem_total > 0 {
                m.mem_used as f64 / m.mem_total as f64 * 100.0
            } else {
                0.0
            };
            tiles.push_str(&tile(
                t("Memória", "Memory", "Memoria"),
                &format!(
                    "{}<small> / {} GB</small>",
                    gigabytes(lang, m.mem_used),
                    gigabytes(lang, m.mem_total)
                ),
                Some(mem_percent),
                &format!(
                    "swap {} / {} GB",
                    gigabytes(lang, m.swap_used),
                    gigabytes(lang, m.swap_total)
                ),
            ));
        }
        Err(error) => problems.push_str(&error_body(
            lang,
            t(
                "Métricas indisponíveis",
                "Metrics unavailable",
                "Métricas no disponibles",
            ),
            error,
        )),
    }
    match &disk {
        Ok((used, total, percent)) => tiles.push_str(&tile(
            t("Disco · /", "Disk · /", "Disco · /"),
            &format!(
                "{}<small> / {}</small>",
                html_escape(used),
                html_escape(total)
            ),
            Some(f64::from(*percent)),
            &format!("{percent}% {}", t("usado", "used", "usado")),
        )),
        Err(error) => problems.push_str(&error_body(
            lang,
            t(
                "Uso de disco indisponível",
                "Disk usage unavailable",
                "Uso de disco no disponible",
            ),
            error,
        )),
    }
    match &interfaces {
        Ok(list) => {
            let primary = list
                .iter()
                .find(|iface| !iface.ipv4.is_empty() && iface.name != "lo");
            match primary {
                Some(iface) => tiles.push_str(&format!(
                    r#"<div class="tile"><span class="tile-label">{} · {}</span><span class="tile-value mono">{}</span><span class="tile-foot"><span class="dot" aria-hidden="true"></span> {}</span></div>"#,
                    t("Rede", "Network", "Red"),
                    html_escape(&iface.name),
                    html_escape(&iface.ipv4),
                    html_escape(&iface.state),
                )),
                None => tiles.push_str(&tile(
                    t("Rede", "Network", "Red"),
                    "—",
                    None,
                    t(
                        "nenhuma interface com IPv4",
                        "no interface with IPv4",
                        "ninguna interfaz con IPv4",
                    ),
                )),
            }
        }
        Err(error) => problems.push_str(&error_body(
            lang,
            t(
                "Interfaces indisponíveis",
                "Interfaces unavailable",
                "Interfaces no disponibles",
            ),
            error,
        )),
    }
    body.push_str(&problems);
    body.push_str(&format!(r#"<div class="grid-4">{tiles}</div>"#));

    // Row 2: health and main services.
    let mut health = String::new();
    let main_services = t(
        "Serviços principais",
        "Main services",
        "Servicios principales",
    );
    let unavailable = t("indisponível", "unavailable", "no disponible");
    let active = t("ativo", "active", "activo");
    let inactive_text = t("inativo", "inactive", "inactivo");
    let updates_label = t("Atualizações", "Updates", "Actualizaciones");
    let mut all_good = true;
    match &services {
        Ok(list) => {
            let inactive: Vec<_> = list
                .iter()
                .filter(|service| service.enabled && !service.active)
                .collect();
            if inactive.is_empty() {
                health.push_str(&kv(
                    "",
                    main_services,
                    t("todos ativos", "all active", "todos activos"),
                ));
            } else {
                all_good = false;
                health.push_str(&kv(
                    "off",
                    main_services,
                    &format!(
                        "{} {}",
                        inactive.len(),
                        t(
                            "habilitado(s) sem rodar",
                            "enabled but not running",
                            "habilitado(s) sin ejecutarse",
                        )
                    ),
                ));
            }
        }
        Err(_) => health.push_str(&kv("warn", main_services, unavailable)),
    }
    match machine.secure_boot {
        Some(true) => health.push_str(&kv("", "Secure Boot", active)),
        Some(false) => {
            all_good = false;
            health.push_str(&kv("warn", "Secure Boot", inactive_text));
        }
        None => {}
    }
    match &firewall {
        Ok(status) if status.enabled => health.push_str(&kv(
            "",
            "Firewall",
            &if status.active_zone.is_empty() {
                active.to_owned()
            } else {
                format!(
                    "{} {}",
                    t("zona", "zone", "zona"),
                    html_escape(&status.active_zone)
                )
            },
        )),
        Ok(_) => {
            all_good = false;
            health.push_str(&kv("off", "Firewall", inactive_text));
        }
        Err(_) => health.push_str(&kv("warn", "Firewall", unavailable)),
    }
    match &updates {
        Ok(status) if !status.error.is_empty() => {
            all_good = false;
            health.push_str(&kv(
                "warn",
                updates_label,
                t(
                    "última verificação falhou",
                    "last check failed",
                    "la última comprobación falló",
                ),
            ));
        }
        Ok(status) if status.in_progress => health.push_str(&kv(
            "warn",
            updates_label,
            t("verificando…", "checking…", "comprobando…"),
        )),
        Ok(status) if status.total_count == 0 => health.push_str(&kv(
            "",
            updates_label,
            t(
                r#"nenhuma pendente <a href="/software">Ver</a>"#,
                r#"none pending <a href="/software">View</a>"#,
                r#"ninguna pendiente <a href="/software">Ver</a>"#,
            ),
        )),
        Ok(status) => {
            all_good = false;
            health.push_str(&kv(
                "warn",
                updates_label,
                &format!(
                    r#"{} {} <a href="/software">{}</a>"#,
                    status.total_count,
                    t("pendente(s)", "pending", "pendiente(s)"),
                    t("Revisar", "Review", "Revisar"),
                ),
            ));
        }
        Err(_) => health.push_str(&kv("warn", updates_label, unavailable)),
    }
    if let Some((dot, value)) = super::diagnostics::dashboard_row(&state, lang).await {
        health.push_str(&kv(
            &dot,
            t(
                "Verificação periódica",
                "Periodic check",
                "Comprobación periódica",
            ),
            &value,
        ));
    }
    if !machine.kernel.is_empty() {
        health.push_str(&kv("", "Kernel", &html_escape(&machine.kernel)));
    }
    let health_badge = if all_good {
        format!(
            r#"<span class="badge on">{}</span>"#,
            t("Tudo em ordem", "All good", "Todo en orden")
        )
    } else {
        format!(
            r#"<span class="badge warn">{}</span>"#,
            t("Atenção", "Attention", "Atención")
        )
    };

    let services_panel = match &services {
        Ok(list) => {
            let mut sorted: Vec<_> = list.iter().collect();
            sorted.sort_by(|a, b| a.label.cmp(&b.label));
            let rows: String = sorted
                .iter()
                .take(6)
                .map(|service| {
                    let (dot, text) = if service.active {
                        ("", active)
                    } else if service.enabled {
                        ("off", inactive_text)
                    } else {
                        ("warn", t("desabilitado", "disabled", "deshabilitado"))
                    };
                    kv(dot, &html_escape(&service.label), text)
                })
                .collect();
            format!(r#"<div class="kv">{rows}</div>"#)
        }
        Err(error) => error_body(
            lang,
            t(
                "Serviços indisponíveis",
                "Services unavailable",
                "Servicios no disponibles",
            ),
            error,
        ),
    };
    body.push_str(&format!(
        r#"<div class="grid-2">
<section class="panel"><div class="panel-head"><h3>{}</h3>{health_badge}</div><div class="kv">{health}</div></section>
<section class="panel"><div class="panel-head"><h3>{main_services}</h3><a href="/servicos">{}</a></div>{services_panel}</section>
</div>"#,
        t("Saúde", "Health", "Salud"),
        t("Gerenciar", "Manage", "Gestionar"),
    ));

    // Row 3: activity recorded by this panel.
    let entries = state.audit.recent(8);
    let activity = if entries.is_empty() {
        format!(
            r#"<p class="empty">{}</p>"#,
            t(
                "Nenhuma ação registrada desde que o painel subiu.",
                "No action recorded since the panel started.",
                "Ninguna acción registrada desde que se inició el panel.",
            )
        )
    } else {
        let rows: String = entries
            .iter()
            .map(|entry| {
                format!(
                    r#"<span class="t">{}</span><span>{}</span><span class="who">{} · {}</span>"#,
                    html_escape(&entry.when),
                    html_escape(&entry.text),
                    html_escape(&entry.user),
                    html_escape(&entry.address),
                )
            })
            .collect();
        format!(r#"<div class="activity">{rows}</div>"#)
    };
    body.push_str(&format!(
        r#"<section class="panel"><div class="panel-head"><h3>{}</h3><a href="/logs">{}</a></div>{activity}</section>"#,
        t("Atividade recente", "Recent activity", "Actividad reciente"),
        t("Ver logs", "View logs", "Ver registros"),
    ));

    let subtitle = format!(
        "{} · {} {}",
        if machine.edition.is_empty() {
            html_escape(machine.arch)
        } else {
            html_escape(&machine.edition)
        },
        t("ligado há", "up for", "encendido hace"),
        html_escape(&host::uptime()),
    );
    let actions = format!(
        r#"<a class="button" href="/software">{}</a><a class="button primary" href="/terminal">{}</a>"#,
        t(
            "Verificar atualizações",
            "Check for updates",
            "Buscar actualizaciones"
        ),
        t("Abrir terminal", "Open terminal", "Abrir terminal"),
    );
    render_with(
        t("Visão geral", "Overview", "Resumen"),
        "/",
        &user,
        &subtitle,
        &actions,
        body,
    )
}
