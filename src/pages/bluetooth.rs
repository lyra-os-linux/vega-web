use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::BluetoothClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let client = state.dbus.bluetooth();
    let mut body = String::new();
    let (yes, no) = (t("sim", "yes", "sí"), t("não", "no", "no"));

    match client.status().await {
        Ok(status) if status.available => {
            body.push_str(&format!(
                r#"<div class="cards">
<div class="card">{}<strong>{}</strong></div>
<div class="card">{}<strong><span class="badge {}">{}</span></strong></div>
<div class="card">{}<strong><span class="badge {}">{}</span></strong></div>
</div>"#,
                t("Controlador", "Controller", "Controlador"),
                html_escape(&status.controller_name),
                t("Ligado", "Powered", "Encendido"),
                if status.powered { "on" } else { "off" },
                if status.powered { yes } else { no },
                t("Descobrindo", "Discovering", "Buscando"),
                if status.scanning { "on" } else { "off" },
                if status.scanning { yes } else { no },
            ));
        }
        Ok(_) => body.push_str(&format!(
            "<p>{}</p>",
            t(
                "Sem controlador Bluetooth nesta máquina.",
                "No Bluetooth controller on this machine.",
                "No hay controlador Bluetooth en esta máquina.",
            )
        )),
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Status do Bluetooth indisponível",
                "Bluetooth status unavailable",
                "Estado de Bluetooth no disponible",
            ),
            error,
        )),
    }

    match client.devices().await {
        Ok(devices) if !devices.is_empty() => {
            let rows: String = devices
                .iter()
                .map(|device| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td></tr>",
                        html_escape(&device.alias),
                        html_escape(&device.address),
                        if device.connected { "on" } else { "off" },
                        if device.connected {
                            t("conectado", "connected", "conectado")
                        } else {
                            t("pareado", "paired", "emparejado")
                        },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<table><thead><tr><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>{rows}</tbody></table>"#,
                t("Dispositivo", "Device", "Dispositivo"),
                t("Endereço", "Address", "Dirección"),
                t("Estado", "State", "Estado"),
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Lista de dispositivos indisponível",
                "Device list unavailable",
                "Lista de dispositivos no disponible",
            ),
            error,
        )),
    }

    render("Bluetooth", "/bluetooth", &user, body)
}
