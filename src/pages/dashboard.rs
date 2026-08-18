use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::{
    MetadataClient, ServicesClient, SnapshotsClient, SoftwareClient, SystemClient,
};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::{gauge_stat, icon_stat};
use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let status = state.dbus.system().status().await;
    let services = state.dbus.services().list().await;
    let snapshots_available = state.dbus.snapshots().available().await;
    // Every administrative login lands here. The daemon answers from its
    // bounded cache and starts one deduplicated refresh when that cache is
    // stale, so repository latency never blocks access to the dashboard.
    let updates = state.dbus.software().request_update_check().await;
    let metadata = state.dbus.metadata().metadata().await;

    let mut body = String::new();

    if let Ok(metadata) = metadata {
        body.push_str(&format!(
            "<p>Perfil do servidor: <strong>{}</strong></p>",
            html_escape(&metadata.profile)
        ));
    }

    match updates {
        Ok(status) if !status.error.is_empty() => body.push_str(&error_body(
            "Última verificação de atualizações falhou",
            html_escape(&status.error),
        )),
        Ok(status) if status.in_progress => body.push_str(&format!(
            "<p><strong>Atualizações:</strong> verificação em andamento; último estado: {} pacote(s) pendente(s).</p>",
            status.total_count
        )),
        Ok(status) if status.total_count == 0 => body.push_str("<p><strong>Atualizações:</strong> sistema em dia.</p>"),
        Ok(status) => body.push_str(&format!(
            r#"<p class="notice"><strong>Atenção:</strong> {} atualização(ões) pendente(s). <a href="/software?tab=updates">Revisar atualizações</a>.</p>"#,
            status.total_count
        )),
        Err(error) => body.push_str(&error_body("Não foi possível verificar atualizações", error)),
    }

    match status {
        Ok(status) => {
            body.push_str(&format!(
                r#"<div class="cards">
{}
{}
</div>"#,
                icon_stat("dashboard", "Distribuição", &html_escape(&status.distro)),
                icon_stat("software", "Versão do Vega", &html_escape(&status.version)),
            ));
        }
        Err(error) => body.push_str(&error_body("Status do sistema indisponível", error)),
    }

    match services {
        Ok(list) => {
            let total = list.len();
            let active = list.iter().filter(|service| service.active).count();
            let percent = if total > 0 {
                active as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            body.push_str(&format!(
                r#"<div class="cards">
{}
</div>"#,
                gauge_stat(
                    "services",
                    "Serviços ativos",
                    &format!("{active} / {total}"),
                    percent,
                ),
            ));
        }
        Err(error) => body.push_str(&error_body("Serviços indisponíveis", error)),
    }

    match snapshots_available {
        Ok(true) => body.push_str(r#"<p>Snapshots disponíveis nesta máquina — veja a página <a href="/snapshots">Snapshots</a>.</p>"#),
        Ok(false) => body.push_str("<p>Sem suporte a snapshots (Snapper/Timeshift) nesta máquina.</p>"),
        Err(error) => body.push_str(&error_body("Status de snapshots indisponível", error)),
    }

    render("Painel", "/", &user.0, body)
}
