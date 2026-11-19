use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::MonitorClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::{bar, gauge_stat, icon_stat};
use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let client = state.dbus.monitor();
    let mut body = String::new();

    match client.metrics().await {
        Ok(metrics) => {
            let mem_percent = if metrics.mem_total > 0 {
                metrics.mem_used as f64 / metrics.mem_total as f64 * 100.0
            } else {
                0.0
            };
            let swap_percent = if metrics.swap_total > 0 {
                metrics.swap_used as f64 / metrics.swap_total as f64 * 100.0
            } else {
                0.0
            };

            let gpu_tile = if metrics.gpu_percent >= 0.0 {
                gauge_stat(
                    "gpu",
                    "GPU",
                    &format!("{:.1}%", metrics.gpu_percent),
                    metrics.gpu_percent,
                )
            } else {
                icon_stat(
                    "gpu",
                    "GPU",
                    t("Uso indisponível", "Usage unavailable", "Uso no disponible"),
                )
            };
            let swap_tile = if metrics.swap_total > 0 {
                gauge_stat(
                    "swap",
                    "Swap",
                    &format!(
                        "{} / {}",
                        format_bytes(metrics.swap_used),
                        format_bytes(metrics.swap_total)
                    ),
                    swap_percent,
                )
            } else {
                icon_stat(
                    "swap",
                    "Swap",
                    t(
                        "Sem swap configurado",
                        "No swap configured",
                        "Sin swap configurado",
                    ),
                )
            };

            body.push_str(&format!(
                r#"<div class="cards">
{cpu}{gpu}{mem}{swap}
{disk_read}{disk_write}{net_rx}{net_tx}
</div>"#,
                cpu = gauge_stat(
                    "cpu",
                    "CPU",
                    &format!("{:.1}%", metrics.cpu_percent),
                    metrics.cpu_percent
                ),
                gpu = gpu_tile,
                mem = gauge_stat(
                    "memory",
                    t("Memória", "Memory", "Memoria"),
                    &format!(
                        "{} / {}",
                        format_bytes(metrics.mem_used),
                        format_bytes(metrics.mem_total)
                    ),
                    mem_percent,
                ),
                swap = swap_tile,
                disk_read = icon_stat(
                    "disk",
                    t("Disco (leitura)", "Disk (read)", "Disco (lectura)"),
                    &format!("{}/s", format_bytes(metrics.disk_read_bytes))
                ),
                disk_write = icon_stat(
                    "disk",
                    t("Disco (escrita)", "Disk (write)", "Disco (escritura)"),
                    &format!("{}/s", format_bytes(metrics.disk_write_bytes))
                ),
                net_rx = icon_stat(
                    "download",
                    t("Rede (rx)", "Network (rx)", "Red (rx)"),
                    &format!("{}/s", format_bytes(metrics.net_rx_bytes))
                ),
                net_tx = icon_stat(
                    "upload",
                    t("Rede (tx)", "Network (tx)", "Red (tx)"),
                    &format!("{}/s", format_bytes(metrics.net_tx_bytes))
                ),
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Métricas do sistema indisponíveis",
                "System metrics unavailable",
                "Métricas del sistema no disponibles",
            ),
            error,
        )),
    }

    match client.list_processes().await {
        Ok(mut processes) => {
            processes.sort_by(|a, b| b.cpu_percent.get().total_cmp(&a.cpu_percent.get()));
            let rows: String = processes
                .iter()
                .take(20)
                .map(|process| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%{}</td><td>{}</td></tr>",
                        process.pid,
                        html_escape(&process.name),
                        html_escape(&process.user),
                        process.cpu_percent.get(),
                        bar(process.cpu_percent.get()),
                        format_bytes(process.memory),
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<h3>{}</h3>
<table><thead><tr><th>PID</th><th>{}</th><th>{}</th><th>CPU</th><th>{}</th></tr></thead><tbody>{rows}</tbody></table>"#,
                t(
                    "Processos (top 20 por CPU)",
                    "Processes (top 20 by CPU)",
                    "Procesos (top 20 por CPU)",
                ),
                t("Nome", "Name", "Nombre"),
                t("Usuário", "User", "Usuario"),
                t("Memória", "Memory", "Memoria"),
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Lista de processos indisponível",
                "Process list unavailable",
                "Lista de procesos no disponible",
            ),
            error,
        )),
    }

    render("Monitor", "/monitor", &user, body)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}
