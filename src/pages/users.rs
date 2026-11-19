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
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
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
                            t("Retirar administrador", "Remove administrator", "Quitar administrador"),
                            "set-admin",
                            &[("name", &account.username), ("enabled", "false")],
                        )
                    } else {
                        actions.button(
                            t("Tornar administrador", "Make administrator", "Hacer administrador"),
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
                            match lang {
                            vega_web::lang::Lang::Pt => r#"<span class="badge on">administrador</span>"#,
                            vega_web::lang::Lang::En => r#"<span class="badge on">administrator</span>"#,
                            vega_web::lang::Lang::Es => r#"<span class="badge on">administrador</span>"#,
                        }
                        } else {
                            ""
                        },
                    )
                })
                .collect();
            (
                format!(
                    "{} {} · {admins} {}",
                    users.len(),
                    t("conta(s)", "account(s)", "cuenta(s)"),
                    t("administrador(es)", "administrator(s)", "administrador(es)"),
                ),
                format!(
                    r#"{}<table>
<thead><tr><th>{}</th><th>{}</th><th></th><th></th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
                    actions.notice(),
                    t("Usuário", "User", "Usuario"),
                    t("Grupos", "Groups", "Grupos"),
                ),
            )
        }
        Err(error) => (
            String::new(),
            error_body(
                lang,
                t(
                    "Lista de usuários indisponível",
                    "User list unavailable",
                    "Lista de usuarios no disponible",
                ),
                error,
            ),
        ),
    };
    render_with(
        t("Usuários", "Users", "Usuarios"),
        "/usuarios",
        &user,
        &subtitle,
        "",
        body,
    )
}
