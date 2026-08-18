use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::UsersClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::icon_stat;
use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let body = match state.dbus.users().list().await {
        Ok(mut users) => {
            users.sort_by(|a, b| a.username.cmp(&b.username));
            let admins = users.iter().filter(|account| account.is_admin).count();
            let rows: String = users
                .iter()
                .map(|account| {
                    format!(
                        "<tr><td>{}<br><small>{}</small></td><td>{}</td><td><span class=\"badge {}\">{}</span></td></tr>",
                        html_escape(&account.username),
                        html_escape(&account.full_name),
                        html_escape(&account.groups.join(", ")),
                        if account.is_admin { "on" } else { "off" },
                        if account.is_admin { "administrador" } else { "" },
                    )
                })
                .collect();
            format!(
                r#"<div class="cards">{} {}</div>
<table>
<thead><tr><th>Usuário</th><th>Grupos</th><th></th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                icon_stat("users", "Contas", &users.len().to_string()),
                icon_stat("check", "Administradores", &admins.to_string()),
            )
        }
        Err(error) => error_body("Lista de usuários indisponível", error),
    };

    render("Usuários", "/usuarios", &user.0, body)
}
