use axum::extract::{Extension, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::StorageClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::bar;
use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let mut body = match state.dbus.storage().list().await {
        Ok(volumes) => {
            let rows: String = volumes
                .iter()
                .map(|volume| {
                    format!(
                        "<tr><td>{}<br><small>{}</small></td><td>{}</td><td>{} / {} ({}%){}</td><td>{}</td></tr>",
                        html_escape(&volume.name),
                        html_escape(&volume.model),
                        html_escape(&volume.fs_type),
                        html_escape(&volume.used),
                        html_escape(&volume.size),
                        volume.use_percent,
                        bar(volume.use_percent as f64),
                        html_escape(&volume.mountpoint),
                    )
                })
                .collect();
            format!(
                r#"<table>
<thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                t("Volume", "Volume", "Volumen"),
                t("Sistema de arquivos", "File system", "Sistema de archivos"),
                t("Uso", "Usage", "Uso"),
                t("Ponto de montagem", "Mount point", "Punto de montaje"),
            )
        }
        Err(error) => error_body(
            lang,
            t(
                "Lista de volumes indisponível",
                "Volume list unavailable",
                "Lista de volúmenes no disponible",
            ),
            error,
        ),
    };
    body.push_str(&super::diagnostics::cleanup_section(&state, &jar, &user));

    render(
        t("Armazenamento", "Storage", "Almacenamiento"),
        "/armazenamento",
        &user,
        body,
    )
}
