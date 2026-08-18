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
                icon_stat("gpu", "GPU", "Uso indisponível")
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
                icon_stat("swap", "Swap", "Sem swap configurado")
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
                    "Memória",
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
                    "Disco (leitura)",
                    &format!("{}/s", format_bytes(metrics.disk_read_bytes))
                ),
                disk_write = icon_stat(
                    "disk",
                    "Disco (escrita)",
                    &format!("{}/s", format_bytes(metrics.disk_write_bytes))
                ),
                net_rx = icon_stat(
                    "download",
                    "Rede (rx)",
                    &format!("{}/s", format_bytes(metrics.net_rx_bytes))
                ),
                net_tx = icon_stat(
                    "upload",
                    "Rede (tx)",
                    &format!("{}/s", format_bytes(metrics.net_tx_bytes))
                ),
            ));
        }
        Err(error) => body.push_str(&error_body("Métricas do sistema indisponíveis", error)),
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
                r#"<h3>Processos (top 20 por CPU)</h3>
<table><thead><tr><th>PID</th><th>Nome</th><th>Usuário</th><th>CPU</th><th>Memória</th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Err(error) => body.push_str(&error_body("Lista de processos indisponível", error)),
    }

    render("Monitor", "/monitor", &user.0, body)
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
