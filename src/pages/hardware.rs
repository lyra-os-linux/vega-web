use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::{HardwareClient, KernelClient};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let mut body = String::new();

    match state.dbus.hardware().inventory().await {
        Ok(inventory) => body.push_str(&format!(
            r#"<div class="cards">
{}
{}
{}
</div>"#,
            icon_stat("cpu", "CPU", &html_escape(&inventory.cpu)),
            icon_stat("gpu", "GPU", &html_escape(&inventory.gpu)),
            icon_stat("memory", "RAM", &html_escape(&inventory.ram)),
        )),
        Err(error) => body.push_str(&error_body("Inventário de hardware indisponível", error)),
    }

    match state.dbus.hardware().firmware_status().await {
        Ok(status) => body.push_str(&format!("<p>Firmware: {}</p>", html_escape(&status))),
        Err(error) => body.push_str(&error_body("Status de firmware indisponível", error)),
    }

    let kernel = state.dbus.kernel();

    match kernel.boot_status().await {
        Ok(boot) => body.push_str(&format!(
            r#"<h3>Boot</h3>
<div class="cards">
{}
{}
{}
</div>
<p>cmdline: <code>{}</code></p>"#,
            icon_stat("hardware", "Bootloader", &html_escape(&boot.loader)),
            icon_stat("check", "Entrada padrão", &html_escape(&boot.default_entry)),
            icon_stat("datetime", "Timeout", &format!("{}s", boot.timeout)),
            html_escape(&boot.cmdline),
        )),
        Err(error) => body.push_str(&error_body("Status de boot indisponível", error)),
    }

    match kernel.list_installed().await {
        Ok(installed) => {
            let items: String = installed
                .iter()
                .map(|kernel| format!("<li>{}</li>", html_escape(kernel)))
                .collect();
            body.push_str(&format!("<h3>Kernels instalados</h3><ul>{items}</ul>"));
        }
        Err(error) => body.push_str(&error_body(
            "Lista de kernels instalados indisponível",
            error,
        )),
    }

    render("Hardware e Kernel", "/hardware", &user.0, body)
}
