use super::{html_escape, render};
use crate::auth::CurrentUser;
use crate::state::{AppState, SESSION_COOKIE};
use axum::extract::{ConnectInfo, Extension, Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;
use vega_web::admin_ipc::{self, Operation};
use zeroize::Zeroizing;

pub fn notice(state: &AppState) -> String {
    if state.admin_socket.is_some() {
        r#"<p class="notice"><a href="/administracao">Instalar pacote ou abrir porta no firewall</a>. Cada alteração exige sua senha e permissão administrativa.</p>"#.to_owned()
    } else {
        super::ADMINISTRATION_UNAVAILABLE_NOTICE.to_owned()
    }
}

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(CurrentUser(username)): Extension<CurrentUser>,
) -> Response {
    if state.admin_socket.is_none() {
        return (
            StatusCode::FORBIDDEN,
            render(
                "Administração",
                "/software",
                &username,
                super::ADMINISTRATION_UNAVAILABLE_NOTICE.to_owned(),
            ),
        )
            .into_response();
    }
    let Some(lease) = jar
        .get(SESSION_COOKIE)
        .and_then(|cookie| state.sessions.lease(cookie.value(), Instant::now()))
    else {
        return Redirect::to("/login").into_response();
    };
    if username != lease.username {
        return Redirect::to("/login").into_response();
    }
    let csrf = html_escape(&lease.csrf);
    let body = format!(
        r#"<p>As alterações exigem uma conta administrativa do grupo <code>wheel</code>. Confirme a operação informando sua senha novamente.</p>
<h3>Instalar pacote RPM</h3>
<form method="post" action="/administracao">
<input type="hidden" name="action" value="install"><input type="hidden" name="csrf" value="{csrf}">
<label>Nome do pacote<br><input name="package" required maxlength="200" autocomplete="off"></label>
<label>Senha<br><input type="password" name="password" required autocomplete="current-password" maxlength="4096"></label>
<button type="submit">Autorizar instalação</button></form>
<h3>Abrir uma porta no firewall</h3>
<form method="post" action="/administracao">
<input type="hidden" name="action" value="add-port"><input type="hidden" name="csrf" value="{csrf}">
<label>Porta<br><input type="number" name="port" min="1" max="65535" required></label>
<label>Protocolo<br><select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
<label>Senha<br><input type="password" name="password" required autocomplete="current-password" maxlength="4096"></label>
<button type="submit">Autorizar abertura da porta</button></form>
<p><a href="/software">Voltar para Software</a> · <a href="/rede">Voltar para Rede</a></p>"#
    );
    render("Administração", "/software", &username, body).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionForm {
    action: String,
    csrf: String,
    password: String,
    package: Option<String>,
    port: Option<String>,
    protocol: Option<String>,
}

impl ActionForm {
    fn operation(&self) -> Option<Operation> {
        match self.action.as_str() {
            "install" if self.port.is_none() && self.protocol.is_none() => {
                Operation::install(self.package.as_deref()?).ok()
            }
            "add-port" if self.package.is_none() => {
                Operation::port(self.port.as_deref()?, self.protocol.as_deref()?).ok()
            }
            _ => None,
        }
    }
}

fn matching_csrf(expected: &str, received: &str) -> bool {
    expected.len() == received.len()
        && expected
            .bytes()
            .zip(received.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

pub async fn execute(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    jar: PrivateCookieJar,
    Extension(CurrentUser(username)): Extension<CurrentUser>,
    Form(mut form): Form<ActionForm>,
) -> Response {
    // Move the secret out before validation so every early return clears it.
    let password = Zeroizing::new(std::mem::take(&mut form.password));
    let Some(path) = state.admin_socket.as_deref() else {
        return (StatusCode::FORBIDDEN, "Administração indisponível.").into_response();
    };
    let Some(mut lease) = jar
        .get(SESSION_COOKIE)
        .and_then(|cookie| state.sessions.lease(cookie.value(), Instant::now()))
    else {
        return (StatusCode::UNAUTHORIZED, "Sessão encerrada.").into_response();
    };
    if lease.username != username || !matching_csrf(&lease.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "Confirmação de sessão inválida.").into_response();
    }
    let Some(operation) = form.operation() else {
        return (StatusCode::BAD_REQUEST, "Operação ou parâmetros inválidos.").into_response();
    };
    if password.is_empty()
        || password.len() > vega_web::auth_ipc::MAX_PASSWORD
        || password.contains('\0')
    {
        return (StatusCode::BAD_REQUEST, "Senha necessária.").into_response();
    }
    let ip = remote.ip().to_string();
    if state
        .login_limiter
        .check(&ip, &username, Instant::now())
        .is_some()
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Muitas tentativas; aguarde.").into_response();
    }
    let Ok(_permit) = state.pam_slots.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Autenticação ocupada; tente novamente.",
        )
            .into_response();
    };
    let request = admin_ipc::Request {
        username: username.clone(),
        password,
        session: lease.admin_binding,
        operation: operation.clone(),
    };
    let outcome = tokio::select! {
        biased;
        _ = lease.revoked() => {
            eprintln!("vega-web: user={username:?} action={} outcome=session-revoked", operation.action_id());
            return (StatusCode::UNAUTHORIZED, "Sessão encerrada. Entre novamente e confira o estado da operação antes de repetir.").into_response();
        },
        result = admin_ipc::execute(Path::new(path), request) => result,
    };
    match outcome {
        Ok(result) => {
            state.login_limiter.success(&ip, &username);
            eprintln!("vega-web: id={} user={username:?} action={} transaction={} outcome=accepted",
                      result.audit_id, operation.action_id(), result.transaction);
            let (status, message) = match operation {
                Operation::InstallNative(name) => (StatusCode::ACCEPTED, format!(
                    "Solicitação de instalação de <strong>{}</strong> aceita. Transação {}. A instalação ainda precisa concluir; confira o estado do pacote antes de repetir.", html_escape(&name), result.transaction)),
                Operation::AddPort { port, tcp } => (StatusCode::OK, format!("Porta {port}/{} adicionada ao firewall.", if tcp { "tcp" } else { "udp" })),
            };
            (status, render("Administração", "/software", &username,
                format!("<p>{message}</p><p><a href=\"/software\">Software</a> · <a href=\"/rede\">Rede</a></p>"))).into_response()
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let delay = state.login_limiter.failure(&ip, &username, Instant::now());
            tokio::time::sleep(delay).await;
            (StatusCode::FORBIDDEN, "Operação não autorizada. Verifique suas credenciais e permissões.").into_response()
        }
        Err(_) => (StatusCode::BAD_GATEWAY,
            "Não foi possível confirmar o resultado. Confira o estado da operação antes de repetir.").into_response(),
    }
}
