use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::MonitorClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let client = state.dbus.monitor();
    let mut body = String::new();

    match client.metrics().await {
        Ok(metrics) => {
            body.push_str(&format!(
                r#"<div class="cards">
<div class="card">CPU<strong>{:.1}%</strong></div>
<div class="card">Memória<strong>{} / {}</strong></div>
<div class="card">Swap<strong>{} / {}</strong></div>
<div class="card">Disco (leitura/escrita)<strong>{}/s / {}/s</strong></div>
<div class="card">Rede (rx/tx)<strong>{}/s / {}/s</strong></div>
</div>"#,
                metrics.cpu_percent,
                format_bytes(metrics.mem_used),
                format_bytes(metrics.mem_total),
                format_bytes(metrics.swap_used),
                format_bytes(metrics.swap_total),
                format_bytes(metrics.disk_read_bytes),
                format_bytes(metrics.disk_write_bytes),
                format_bytes(metrics.net_rx_bytes),
                format_bytes(metrics.net_tx_bytes),
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
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%</td><td>{}</td></tr>",
                        process.pid,
                        html_escape(&process.name),
                        html_escape(&process.user),
                        process.cpu_percent.get(),
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
