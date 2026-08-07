use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::ServicesClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let body = match state.dbus.services().list().await {
        Ok(mut services) => {
            services.sort_by(|a, b| a.label.cmp(&b.label));
            let rows: String = services
                .iter()
                .map(|service| {
                    format!(
                        r#"<tr>
<td>{}<br><small>{}</small></td>
<td><span class="badge {}">{}</span></td>
<td><span class="badge {}">{}</span></td>
</tr>"#,
                        html_escape(&service.label),
                        html_escape(&service.description),
                        if service.enabled { "on" } else { "off" },
                        if service.enabled {
                            "habilitado"
                        } else {
                            "desabilitado"
                        },
                        if service.active { "on" } else { "off" },
                        if service.active { "ativo" } else { "inativo" },
                    )
                })
                .collect();
            format!(
                r#"<p>Somente leitura nesta versão — ligar/desligar serviços chega numa fase seguinte.</p>
<table>
<thead><tr><th>Serviço</th><th>Inicialização</th><th>Estado atual</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#
            )
        }
        Err(error) => error_body("Lista de serviços indisponível", error),
    };

    render("Serviços", "/servicos", &user.0, body)
}
