use axum::extract::{Extension, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::UsersClient;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{Actions, error_body, html_escape, render_with};

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let actions = Actions::new(&state, &jar, &user);
    let (subtitle, body) = match state.dbus.users().list().await {
        Ok(mut users) => {
            users.sort_by(|a, b| a.username.cmp(&b.username));
            let admins = users.iter().filter(|account| account.is_admin).count();
            let rows: String = users
                .iter()
                .map(|account| {
                    // The signed-in administrator never removes their own
                    // privilege from here; root is not managed by the panel.
                    let own = account.username == user.name || account.username == "root";
                    let action = if own {
                        String::new()
                    } else if account.is_admin {
                        actions.button(
                            "Retirar administrador",
                            "set-admin",
                            &[("name", &account.username), ("enabled", "false")],
                        )
                    } else {
                        actions.button(
                            "Tornar administrador",
                            "set-admin",
                            &[("name", &account.username), ("enabled", "true")],
                        )
                    };
                    format!(
                        r#"<tr><td>{}<small>{}</small></td><td>{}</td><td>{}</td><td><div class="row-actions">{action}</div></td></tr>"#,
                        html_escape(&account.username),
                        html_escape(&account.full_name),
                        html_escape(&account.groups.join(", ")),
                        if account.is_admin {
                            r#"<span class="badge on">administrador</span>"#
                        } else {
                            ""
                        },
                    )
                })
                .collect();
            (
                format!("{} conta(s) · {admins} administrador(es)", users.len()),
                format!(
                    r#"{}<table>
<thead><tr><th>Usuário</th><th>Grupos</th><th></th><th></th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                    actions.notice()
                ),
            )
        }
        Err(error) => (
            String::new(),
            error_body("Lista de usuários indisponível", error),
        ),
    };
    render_with("Usuários", "/usuarios", &user, &subtitle, "", body)
}
