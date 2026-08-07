use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::SnapshotsClient;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let client = state.dbus.snapshots();

    let body = match client.available().await {
        Ok(false) => {
            "<p>Sem suporte a snapshots (Snapper/Timeshift) nesta máquina.</p>".to_string()
        }
        Ok(true) => match client.list().await {
            Ok(mut snapshots) => {
                snapshots.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.id));
                let rows: String = snapshots
                    .iter()
                    .map(|snapshot| {
                        format!(
                            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                            snapshot.id,
                            format_timestamp(snapshot.timestamp),
                            html_escape(&snapshot.trigger),
                            html_escape(&snapshot.description),
                        )
                    })
                    .collect();
                format!(
                    r#"<p>Somente leitura nesta versão — criar/reverter snapshots chega numa fase seguinte.</p>
<table>
<thead><tr><th>ID</th><th>Data</th><th>Origem</th><th>Descrição</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#
                )
            }
            Err(error) => error_body("Lista de snapshots indisponível", error),
        },
        Err(error) => error_body("Status de snapshots indisponível", error),
    };

    render("Snapshots", "/snapshots", &user.0, body)
}

fn format_timestamp(unix_seconds: i64) -> String {
    let Ok(datetime) = OffsetDateTime::from_unix_timestamp(unix_seconds) else {
        return unix_seconds.to_string();
    };
    datetime
        .format(&Rfc3339)
        .unwrap_or_else(|_| unix_seconds.to_string())
}
