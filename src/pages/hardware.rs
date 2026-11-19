use axum::extract::{Extension, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::{HardwareClient, KernelClient};
use vega_web::admin_read::{KernelBoot, ReadQuery};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{Actions, cached_read, error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let actions = Actions::new(&state, &jar, &user);
    let mut body = String::new();
    body.push_str(&format!(
        "<p><a href=\"/hardware/diagnostico\">{}</a></p>",
        t(
            "Diagnóstico de saúde",
            "Health diagnostics",
            "Diagnóstico de salud"
        )
    ));

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
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Inventário de hardware indisponível",
                "Hardware inventory unavailable",
                "Inventario de hardware no disponible",
            ),
            error,
        )),
    }

    match state.dbus.hardware().firmware_status().await {
        Ok(status) => body.push_str(&format!("<p>Firmware: {}</p>", html_escape(&status))),
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Status de firmware indisponível",
                "Firmware status unavailable",
                "Estado del firmware no disponible",
            ),
            error,
        )),
    }

    let kernel = state.dbus.kernel();

    let boot = match cached_read::<KernelBoot>(&state, &jar, ReadQuery::KernelBoot) {
        Some(payload) => Ok(payload),
        None => match kernel.boot_status().await {
            Ok(status) => Ok(KernelBoot {
                loader: status.loader,
                default_entry: status.default_entry,
                timeout: status.timeout,
                cmdline: status.cmdline,
                entries: kernel.list_boot_entries().await.unwrap_or_default(),
            }),
            Err(error) => Err(error),
        },
    };
    match boot {
        Ok(boot) => {
            let entries: String = boot
                .entries
                .iter()
                .map(|entry| format!("<li>{}</li>", html_escape(entry)))
                .collect();
            body.push_str(&format!(
                r#"<h3>Boot</h3>
<div class="cards">
{}
{}
{}
</div>
<p>cmdline: <code>{}</code></p>{}"#,
                icon_stat("hardware", "Bootloader", &html_escape(&boot.loader)),
                icon_stat(
                    "check",
                    t("Entrada padrão", "Default entry", "Entrada predeterminada"),
                    &html_escape(&boot.default_entry)
                ),
                icon_stat(
                    "datetime",
                    t("Timeout", "Timeout", "Tiempo de espera"),
                    &format!("{}s", boot.timeout)
                ),
                html_escape(&boot.cmdline),
                if entries.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<h3>{}</h3><ul>{entries}</ul>",
                        t(
                            "Entradas do carregador",
                            "Boot loader entries",
                            "Entradas del cargador"
                        )
                    )
                },
            ))
        }
        Err(error) if actions.enabled() => {
            body.push_str(&actions.unlock(
                ReadQuery::KernelBoot,
                t("Status de boot", "Boot status", "Estado de arranque"),
            ));
            body.push_str(&error_body(
                lang,
                t(
                    "Leitura direta recusada",
                    "Direct read refused",
                    "Lectura directa rechazada",
                ),
                error,
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Status de boot indisponível",
                "Boot status unavailable",
                "Estado de arranque no disponible",
            ),
            error,
        )),
    }

    match kernel.list_installed().await {
        Ok(installed) => {
            let items: String = installed
                .iter()
                .map(|kernel| format!("<li>{}</li>", html_escape(kernel)))
                .collect();
            body.push_str(&format!(
                "<h3>{}</h3><ul>{items}</ul>",
                t(
                    "Kernels instalados",
                    "Installed kernels",
                    "Kernels instalados"
                )
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Lista de kernels instalados indisponível",
                "Installed kernel list unavailable",
                "Lista de kernels instalados no disponible",
            ),
            error,
        )),
    }

    render(
        t(
            "Hardware e Kernel",
            "Hardware and Kernel",
            "Hardware y núcleo",
        ),
        "/hardware",
        &user,
        body,
    )
}
