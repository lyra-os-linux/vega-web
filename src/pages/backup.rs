use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::BackupClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let body = match state.dbus.backup().list_configs().await {
        Ok(configs) => {
            if configs.is_empty() {
                "<p>Nenhuma configuração de backup ainda.</p>".to_string()
            } else {
                let destinations = configs
                    .iter()
                    .map(|config| config.destination.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                let rows: String = configs
                    .iter()
                    .map(|config| {
                        format!(
                            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                            html_escape(&config.id),
                            html_escape(&config.paths.join(", ")),
                            html_escape(&config.destination),
                            html_escape(&config.frequency),
                        )
                    })
                    .collect();
                format!(
                    r#"<div class="cards">{} {}</div>
<p>Somente leitura nesta versão — criar/rodar backups chega numa fase seguinte.</p>
<table>
<thead><tr><th>ID</th><th>Caminhos</th><th>Destino</th><th>Frequência</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                    icon_stat("backup", "Configurações", &configs.len().to_string()),
                    icon_stat("storage", "Destinos", &destinations.to_string()),
                )
            }
        }
        Err(error) => error_body("Lista de configurações de backup indisponível", error),
    };

    render("Backup", "/backup", &user.0, body)
}
