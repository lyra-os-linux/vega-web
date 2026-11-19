use axum::extract::{Extension, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::BackupClient;
use vega_web::admin_read::{BackupConfig, BackupConfigs, ReadQuery};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{Actions, cached_read, error_body, html_escape, render_with};

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let actions = Actions::new(&state, &jar, &user);
    // The session's own read (fetched with the user's identity) wins; the
    // direct query only works where the service account is allowed.
    let configs: Result<BackupConfigs, _> =
        match cached_read::<BackupConfigs>(&state, &jar, ReadQuery::BackupConfigs) {
            Some(payload) => Ok(payload),
            None => state
                .dbus
                .backup()
                .list_configs()
                .await
                .map(|configs| BackupConfigs {
                    configs: configs
                        .into_iter()
                        .map(|config| BackupConfig {
                            id: config.id,
                            paths: config.paths,
                            destination: config.destination,
                            frequency: config.frequency,
                        })
                        .collect(),
                }),
        };
    let body = match configs {
        Ok(BackupConfigs { configs }) => {
            if configs.is_empty() {
                format!(
                    r#"<p class="empty">{}</p>"#,
                    t(
                        "Nenhuma configuração de backup ainda.",
                        "No backup configuration yet.",
                        "Todavía no hay ninguna configuración de copia de seguridad.",
                    )
                )
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
<table>
<thead><tr><th>ID</th><th>{}</th><th>{}</th><th>{}</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                    icon_stat(
                        "backup",
                        t("Configurações", "Configurations", "Configuraciones"),
                        &configs.len().to_string()
                    ),
                    icon_stat(
                        "storage",
                        t("Destinos", "Destinations", "Destinos"),
                        &destinations.to_string()
                    ),
                    t("Caminhos", "Paths", "Rutas"),
                    t("Destino", "Destination", "Destino"),
                    t("Frequência", "Frequency", "Frecuencia"),
                )
            }
        }
        Err(error) if actions.enabled() => {
            actions.unlock(
                ReadQuery::BackupConfigs,
                t(
                    "Configurações de backup",
                    "Backup configurations",
                    "Configuraciones de copia de seguridad",
                ),
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
                "Lista de configurações de backup indisponível",
                "Backup configuration list unavailable",
                "Lista de configuraciones de copia de seguridad no disponible",
            ),
            error,
        ),
    };
    render_with("Backup", "/backup", &user, "", "", body)
}
