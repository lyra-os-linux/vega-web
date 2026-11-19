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
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let actions = Actions::new(&state, &jar, &user);
    let data = match cached_read::<Snapshots>(&state, &jar, ReadQuery::Snapshots) {
        Some(payload) => Ok(payload),
        None => direct(&state).await,
    };
    let body = match data {
        Ok(Snapshots {
            available: false, ..
        }) => format!(
            r#"<p class="empty">{}</p>"#,
            t(
                "Sem suporte a snapshots (Snapper/Timeshift) nesta máquina.",
                "No snapshot support (Snapper/Timeshift) on this machine.",
                "Sin soporte de instantáneas (Snapper/Timeshift) en esta máquina.",
            )
        ),
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
                format!(
                    r#"<p class="empty">{}</p>"#,
                    t(
                        "Nenhum snapshot ainda.",
                        "No snapshots yet.",
                        "Todavía no hay instantáneas.",
                    )
                )
            } else {
                format!(
                    r#"<table>
<thead><tr><th>ID</th><th>{}</th><th>{}</th><th>{}</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                    t("Data", "Date", "Fecha"),
                    t("Origem", "Origin", "Origen"),
                    t("Descrição", "Description", "Descripción"),
                )
            };
            format!(
                r#"<div class="cards">{} {}</div>{table}"#,
                icon_stat(
                    "snapshots",
                    t("Snapshots", "Snapshots", "Instantáneas"),
                    &snapshots.len().to_string()
                ),
                icon_stat(
                    "datetime",
                    t("Mais recente", "Most recent", "Más reciente"),
                    &snapshots
                        .first()
                        .map(|snapshot| format_timestamp(snapshot.timestamp))
                        .unwrap_or_else(|| "—".to_string()),
                ),
            )
        }
        Err(error) if actions.enabled() => {
            actions.unlock(
                ReadQuery::Snapshots,
                t("Snapshots", "Snapshots", "Instantáneas"),
            ) + &error_body(
                lang,
                t(
                    "Leitura direta recusada",
                    "Direct read refused",
                    "Lectura directa rechazada",
                ),
                error,
            )
        }
        Err(error) => error_body(
            lang,
            t(
                "Lista de snapshots indisponível",
                "Snapshot list unavailable",
                "Lista de instantáneas no disponible",
            ),
            error,
        ),
    };
    render_with(
        t("Snapshots", "Snapshots", "Instantáneas"),
        "/snapshots",
        &user,
        "",
        "",
        body,
    )
}

fn format_timestamp(unix_seconds: i64) -> String {
    let Ok(datetime) = OffsetDateTime::from_unix_timestamp(unix_seconds) else {
        return unix_seconds.to_string();
    };
    datetime
        .format(&Rfc3339)
        .unwrap_or_else(|_| unix_seconds.to_string())
}
