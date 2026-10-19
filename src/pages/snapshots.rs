use axum::extract::{Extension, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::SnapshotsClient;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vega_web::admin_read::{ReadQuery, Snapshot, Snapshots};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{Actions, cached_read, error_body, html_escape, render_with};

async fn direct(state: &AppState) -> Result<Snapshots, String> {
    let client = state.dbus.snapshots();
    let available = client.available().await.map_err(|e| e.to_string())?;
    let snapshots = if available {
        client
            .list()
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|snapshot| Snapshot {
                id: snapshot.id,
                timestamp: snapshot.timestamp,
                trigger: snapshot.trigger,
                description: snapshot.description,
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(Snapshots {
        available,
        snapshots,
    })
}

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let actions = Actions::new(&state, &jar, &user);
    let data = match cached_read::<Snapshots>(&state, &jar, ReadQuery::Snapshots) {
        Some(payload) => Ok(payload),
        None => direct(&state).await,
    };
    let body = match data {
        Ok(Snapshots {
            available: false, ..
        }) => r#"<p class="empty">Sem suporte a snapshots (Snapper/Timeshift) nesta máquina.</p>"#
            .to_string(),
        Ok(Snapshots { mut snapshots, .. }) => {
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
            let table = if snapshots.is_empty() {
                r#"<p class="empty">Nenhum snapshot ainda.</p>"#.to_owned()
            } else {
                format!(
                    r#"<table>
<thead><tr><th>ID</th><th>Data</th><th>Origem</th><th>Descrição</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#
                )
            };
            format!(
                r#"<div class="cards">{} {}</div>{table}"#,
                icon_stat("snapshots", "Snapshots", &snapshots.len().to_string()),
                icon_stat(
                    "datetime",
                    "Mais recente",
                    &snapshots
                        .first()
                        .map(|snapshot| format_timestamp(snapshot.timestamp))
                        .unwrap_or_else(|| "—".to_string()),
                ),
            )
        }
        Err(error) if actions.enabled() => {
            actions.unlock(ReadQuery::Snapshots, "Snapshots")
                + &error_body("Leitura direta recusada", error)
        }
        Err(error) => error_body("Lista de snapshots indisponível", error),
    };
    render_with("Snapshots", "/snapshots", &user, "", "", body)
}

fn format_timestamp(unix_seconds: i64) -> String {
    let Ok(datetime) = OffsetDateTime::from_unix_timestamp(unix_seconds) else {
        return unix_seconds.to_string();
    };
    datetime
        .format(&Rfc3339)
        .unwrap_or_else(|_| unix_seconds.to_string())
}
