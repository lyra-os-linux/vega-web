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
    let client = state.dbus.bluetooth();
    let mut body = String::new();

    match client.status().await {
        Ok(status) if status.available => {
            body.push_str(&format!(
                r#"<div class="cards">
<div class="card">Controlador<strong>{}</strong></div>
<div class="card">Ligado<strong><span class="badge {}">{}</span></strong></div>
<div class="card">Descobrindo<strong><span class="badge {}">{}</span></strong></div>
</div>"#,
                html_escape(&status.controller_name),
                if status.powered { "on" } else { "off" },
                if status.powered { "sim" } else { "não" },
                if status.scanning { "on" } else { "off" },
                if status.scanning { "sim" } else { "não" },
            ));
        }
        Ok(_) => body.push_str("<p>Sem controlador Bluetooth nesta máquina.</p>"),
        Err(error) => body.push_str(&error_body("Status do Bluetooth indisponível", error)),
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
                        if device.connected { "conectado" } else { "pareado" },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<table><thead><tr><th>Dispositivo</th><th>Endereço</th><th>Estado</th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body("Lista de dispositivos indisponível", error)),
    }

    render("Bluetooth", "/bluetooth", &user.0, body)
}
