use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::StorageClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let body = match state.dbus.storage().list().await {
        Ok(volumes) => {
            let rows: String = volumes
                .iter()
                .map(|volume| {
                    format!(
                        "<tr><td>{}<br><small>{}</small></td><td>{}</td><td>{} / {} ({}%)</td><td>{}</td></tr>",
                        html_escape(&volume.name),
                        html_escape(&volume.model),
                        html_escape(&volume.fs_type),
                        html_escape(&volume.used),
                        html_escape(&volume.size),
                        volume.use_percent,
                        html_escape(&volume.mountpoint),
                    )
                })
                .collect();
            format!(
                r#"<table>
<thead><tr><th>Volume</th><th>Sistema de arquivos</th><th>Uso</th><th>Ponto de montagem</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#
            )
        }
        Err(error) => error_body("Lista de volumes indisponível", error),
    };

    render("Armazenamento", "/armazenamento", &user.0, body)
}
