use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::{
    FirewallClient, MonitorClient, NetworkClient, ServicesClient, SoftwareClient, SystemClient,
};

use crate::auth::CurrentUser;
use crate::host;
use crate::state::AppState;

use super::{error_body, html_escape, render_with};

fn gigabytes(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1_073_741_824.0).replace('.', ",")
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
                &format!("CPU · {} núcleos", host::cpu_count()),
                &format!("{:.0}<small>%</small>", m.cpu_percent),
                Some(m.cpu_percent),
                &format!("carga {}", html_escape(&host::load_average())),
            ));
            let mem_percent = if m.mem_total > 0 {
                m.mem_used as f64 / m.mem_total as f64 * 100.0
            } else {
                0.0
            };
            tiles.push_str(&tile(
                "Memória",
                &format!(
                    "{}<small> / {} GB</small>",
                    gigabytes(m.mem_used),
                    gigabytes(m.mem_total)
                ),
                Some(mem_percent),
                &format!(
                    "swap {} / {} GB",
                    gigabytes(m.swap_used),
                    gigabytes(m.swap_total)
                ),
            ));
        }
        Err(error) => problems.push_str(&error_body("Métricas indisponíveis", error)),
    }
    match &disk {
        Ok((used, total, percent)) => tiles.push_str(&tile(
            "Disco · /",
            &format!(
                "{}<small> / {}</small>",
                html_escape(used),
                html_escape(total)
            ),
            Some(f64::from(*percent)),
            &format!("{percent}% usado"),
        )),
        Err(error) => problems.push_str(&error_body("Uso de disco indisponível", error)),
    }
    match &interfaces {
        Ok(list) => {
            let primary = list
                .iter()
                .find(|iface| !iface.ipv4.is_empty() && iface.name != "lo");
            match primary {
                Some(iface) => tiles.push_str(&format!(
                    r#"<div class="tile"><span class="tile-label">Rede · {}</span><span class="tile-value mono">{}</span><span class="tile-foot"><span class="dot" aria-hidden="true"></span> {}</span></div>"#,
                    html_escape(&iface.name),
                    html_escape(&iface.ipv4),
                    html_escape(&iface.state),
                )),
                None => tiles.push_str(&tile("Rede", "—", None, "nenhuma interface com IPv4")),
            }
        }
        Err(error) => problems.push_str(&error_body("Interfaces indisponíveis", error)),
    }
    body.push_str(&problems);
    body.push_str(&format!(r#"<div class="grid-4">{tiles}</div>"#));

    // Row 2: health and main services.
    let mut health = String::new();
    let mut all_good = true;
    match &services {
        Ok(list) => {
            let inactive: Vec<_> = list
                .iter()
                .filter(|service| service.enabled && !service.active)
                .collect();
            if inactive.is_empty() {
                health.push_str(&kv("", "Serviços principais", "todos ativos"));
            } else {
                all_good = false;
                health.push_str(&kv(
                    "off",
                    "Serviços principais",
                    &format!("{} habilitado(s) sem rodar", inactive.len()),
                ));
            }
        }
        Err(_) => health.push_str(&kv("warn", "Serviços principais", "indisponível")),
    }
    match machine.secure_boot {
        Some(true) => health.push_str(&kv("", "Secure Boot", "ativo")),
        Some(false) => {
            all_good = false;
            health.push_str(&kv("warn", "Secure Boot", "inativo"));
        }
        None => {}
    }
    match &firewall {
        Ok(status) if status.enabled => health.push_str(&kv(
            "",
            "Firewall",
            &if status.active_zone.is_empty() {
                "ativo".to_owned()
            } else {
                format!("zona {}", html_escape(&status.active_zone))
            },
        )),
        Ok(_) => {
            all_good = false;
            health.push_str(&kv("off", "Firewall", "inativo"));
        }
        Err(_) => health.push_str(&kv("warn", "Firewall", "indisponível")),
    }
    match &updates {
        Ok(status) if !status.error.is_empty() => {
            all_good = false;
            health.push_str(&kv("warn", "Atualizações", "última verificação falhou"));
        }
        Ok(status) if status.in_progress => {
            health.push_str(&kv("warn", "Atualizações", "verificando…"))
        }
        Ok(status) if status.total_count == 0 => health.push_str(&kv(
            "",
            "Atualizações",
            r#"nenhuma pendente <a href="/software">Ver</a>"#,
        )),
        Ok(status) => {
            all_good = false;
            health.push_str(&kv(
                "warn",
                "Atualizações",
                &format!(
                    r#"{} pendente(s) <a href="/software">Revisar</a>"#,
                    status.total_count
                ),
            ));
        }
        Err(_) => health.push_str(&kv("warn", "Atualizações", "indisponível")),
    }
    if !machine.kernel.is_empty() {
        health.push_str(&kv("", "Kernel", &html_escape(&machine.kernel)));
    }
    let health_badge = if all_good {
        r#"<span class="badge on">Tudo em ordem</span>"#
    } else {
        r#"<span class="badge warn">Atenção</span>"#
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
                        ("", "ativo")
                    } else if service.enabled {
                        ("off", "inativo")
                    } else {
                        ("warn", "desabilitado")
                    };
                    kv(dot, &html_escape(&service.label), text)
                })
                .collect();
            format!(r#"<div class="kv">{rows}</div>"#)
        }
        Err(error) => error_body("Serviços indisponíveis", error),
    };
    body.push_str(&format!(
        r#"<div class="grid-2">
<section class="panel"><div class="panel-head"><h3>Saúde</h3>{health_badge}</div><div class="kv">{health}</div></section>
<section class="panel"><div class="panel-head"><h3>Serviços principais</h3><a href="/servicos">Gerenciar</a></div>{services_panel}</section>
</div>"#
    ));

    // Row 3: activity recorded by this panel.
    let entries = state.audit.recent(8);
    let activity = if entries.is_empty() {
        r#"<p class="empty">Nenhuma ação registrada desde que o painel subiu.</p>"#.to_owned()
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
        r#"<section class="panel"><div class="panel-head"><h3>Atividade recente</h3><a href="/logs">Ver logs</a></div>{activity}</section>"#
    ));

    let subtitle = format!(
        "{} · ligado há {}",
        if machine.edition.is_empty() {
            html_escape(machine.arch)
        } else {
            html_escape(&machine.edition)
        },
        html_escape(&host::uptime()),
    );
    let actions = r#"<a class="button" href="/software">Verificar atualizações</a><a class="button primary" href="/terminal">Abrir terminal</a>"#;
    render_with("Visão geral", "/", &user, &subtitle, actions, body)
}
