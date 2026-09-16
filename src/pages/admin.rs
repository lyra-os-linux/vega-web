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
    confirmed: Option<String>,
    language: Option<String>,
}

impl ActionForm {
    fn operation(&self) -> Option<Operation> {
        match self.action.as_str() {
            "install"
                if self.port.is_none()
                    && self.protocol.is_none()
                    && self.confirmed.is_none()
                    && self.language.is_none() =>
            {
                Operation::install(self.package.as_deref()?).ok()
            }
            "add-port"
                if self.package.is_none()
                    && self.confirmed.is_none()
                    && self.language.is_none() =>
            {
                Operation::port(self.port.as_deref()?, self.protocol.as_deref()?).ok()
            }
            "install-nvidia"
                if self.package.is_none()
                    && self.port.is_none()
                    && self.protocol.is_none()
                    && self.confirmed.as_deref() == Some("yes")
                    && self
                        .language
                        .as_deref()
                        .and_then(super::nvidia::Language::parse)
                        .is_some() =>
            {
                Some(Operation::InstallNvidia)
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
    let lang = form
        .language
        .as_deref()
        .and_then(super::nvidia::Language::parse)
        .unwrap_or(super::nvidia::Language::Pt);
    let Some(path) = state.admin_socket.as_deref() else {
        return (
            StatusCode::FORBIDDEN,
            lang.text(
                "Administração indisponível.",
                "Administration unavailable.",
                "Administración no disponible.",
            ),
        )
            .into_response();
    };
    let Some(mut lease) = jar
        .get(SESSION_COOKIE)
        .and_then(|cookie| state.sessions.lease(cookie.value(), Instant::now()))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            lang.text("Sessão encerrada.", "Session ended.", "Sesión finalizada."),
        )
            .into_response();
    };
    if lease.username != username || !matching_csrf(&lease.csrf, &form.csrf) {
        return (
            StatusCode::FORBIDDEN,
            lang.text(
                "Confirmação de sessão inválida.",
                "Invalid session confirmation.",
                "Confirmación de sesión inválida.",
            ),
        )
            .into_response();
    }
    let Some(operation) = form.operation() else {
        return (
            StatusCode::BAD_REQUEST,
            lang.text(
                "Operação ou parâmetros inválidos.",
                "Invalid operation or parameters.",
                "Operación o parámetros inválidos.",
            ),
        )
            .into_response();
    };
    if password.is_empty()
        || password.len() > vega_web::auth_ipc::MAX_PASSWORD
        || password.contains('\0')
    {
        return (
            StatusCode::BAD_REQUEST,
            lang.text(
                "Senha necessária.",
                "Password required.",
                "Contraseña requerida.",
            ),
        )
            .into_response();
    }
    let ip = remote.ip().to_string();
    if state
        .login_limiter
        .check(&ip, &username, Instant::now())
        .is_some()
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            lang.text(
                "Muitas tentativas; aguarde.",
                "Too many attempts; please wait.",
                "Demasiados intentos; espere.",
            ),
        )
            .into_response();
    }
    let Ok(_permit) = state.pam_slots.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            lang.text(
                "Autenticação ocupada; tente novamente.",
                "Authentication busy; try again.",
                "Autenticación ocupada; inténtelo de nuevo.",
            ),
        )
            .into_response();
    };
    let request = admin_ipc::Request {
        username: username.clone(),
        password,
        session: lease.admin_binding,
        operation: operation.clone(),
    };
    let pending_nvidia = if operation == Operation::InstallNvidia {
        let lang = form
            .language
            .as_deref()
            .and_then(super::nvidia::Language::parse)
            .expect("validated language");
        let binding = lease.admin_binding;
        let prepared = tokio::select! {
            biased;
            _=lease.revoked()=>return (StatusCode::UNAUTHORIZED,lang.text("Sessão encerrada.","Session ended.","Sesión finalizada.")).into_response(),
            result=super::nvidia::prepare(&state,binding,lang)=>result,
        };
        match prepared {
            Ok(pending) => Some(pending),
            Err(error) => {
                return (
                    StatusCode::CONFLICT,
                    render(
                        "NVIDIA",
                        "/hardware",
                        &username,
                        format!("<p>{}</p>", html_escape(&error)),
                    ),
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    let outcome = tokio::select! {
        biased;
        _ = lease.revoked() => {
            eprintln!("vega-web: user={username:?} action={} outcome=session-revoked", operation.action_id());
            return (StatusCode::UNAUTHORIZED, lang.text("Sessão encerrada. Entre novamente e confira o estado da operação antes de repetir.","Session ended. Sign in and review the operation status before retrying.","Sesión finalizada. Inicie sesión y revise el estado antes de repetir.")).into_response();
        },
        result = admin_ipc::execute(Path::new(path), request) => result,
    };
    match outcome {
        Ok(result) => {
            state.login_limiter.success(&ip, &username);
            eprintln!("vega-web: id={} user={username:?} action={} transaction={} outcome=accepted",
                      result.audit_id, operation.action_id(), result.transaction);
            if let Some(pending)=pending_nvidia {return pending.accepted(result.transaction,lease)}
            let (status, message) = match operation {
                Operation::InstallNvidia => unreachable!("NVIDIA uses its transaction observer"),
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
            (StatusCode::FORBIDDEN, lang.text("Operação não autorizada. Verifique suas credenciais e permissões.","Operation not authorized. Check your credentials and permissions.","Operación no autorizada. Revise sus credenciales y permisos.")).into_response()
        }
        Err(_) => (StatusCode::BAD_GATEWAY,
            lang.text("Não foi possível confirmar o resultado. Confira o estado da operação antes de repetir.","The result could not be confirmed. Review the operation status before retrying.","No se pudo confirmar el resultado. Revise el estado antes de repetir.")).into_response(),
    }
}
