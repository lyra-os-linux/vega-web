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
use vega_web::admin_read::ReadQuery;
use zeroize::Zeroizing;

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let username = user.name.clone();
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    if state.admin_socket.is_none() {
        return (
            StatusCode::FORBIDDEN,
            render(
                t("Administração", "Administration", "Administración"),
                "/software",
                &user,
                super::unavailable_notice(lang),
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
        r#"<p>{intro}</p>
<h3>{install_title}</h3>
<form method="post" action="/administracao">
<input type="hidden" name="action" value="install"><input type="hidden" name="csrf" value="{csrf}">
<label>{package}<br><input name="package" required maxlength="200" autocomplete="off"></label>
<label>{password}<br><input type="password" name="password" required autocomplete="current-password" maxlength="4096"></label>
<button type="submit">{install}</button></form>
<h3>{port_title}</h3>
<form method="post" action="/administracao">
<input type="hidden" name="action" value="add-port"><input type="hidden" name="csrf" value="{csrf}">
<label>{port}<br><input type="number" name="port" min="1" max="65535" required></label>
<label>{protocol}<br><select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
<label>{password}<br><input type="password" name="password" required autocomplete="current-password" maxlength="4096"></label>
<button type="submit">{open_port}</button></form>
<p><a href="/software">{back_software}</a> · <a href="/rede">{back_network}</a></p>"#,
        intro = t(
            "As alterações exigem uma conta administrativa do grupo <code>wheel</code>. Confirme a operação informando sua senha novamente.",
            "Changes require an administrative account in the <code>wheel</code> group. Confirm the operation by entering your password again.",
            "Los cambios requieren una cuenta administrativa del grupo <code>wheel</code>. Confirme la operación introduciendo de nuevo su contraseña.",
        ),
        install_title = t(
            "Instalar pacote RPM",
            "Install RPM package",
            "Instalar paquete RPM"
        ),
        package = t("Nome do pacote", "Package name", "Nombre del paquete"),
        password = t("Senha", "Password", "Contraseña"),
        install = t(
            "Autorizar instalação",
            "Authorize installation",
            "Autorizar instalación"
        ),
        port_title = t(
            "Abrir uma porta no firewall",
            "Open a port in the firewall",
            "Abrir un puerto en el firewall",
        ),
        port = t("Porta", "Port", "Puerto"),
        protocol = t("Protocolo", "Protocol", "Protocolo"),
        open_port = t(
            "Autorizar abertura da porta",
            "Authorize opening the port",
            "Autorizar la apertura del puerto",
        ),
        back_software = t(
            "Voltar para Software",
            "Back to Software",
            "Volver a Software"
        ),
        back_network = t("Voltar para Rede", "Back to Network", "Volver a Red"),
    );
    render(
        t("Administração", "Administration", "Administración"),
        "/software",
        &user,
        body,
    )
    .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionForm {
    action: String,
    csrf: String,
    #[serde(default)]
    password: Option<String>,
    package: Option<String>,
    port: Option<String>,
    protocol: Option<String>,
    name: Option<String>,
    enabled: Option<String>,
    timezone: Option<String>,
    ntp: Option<String>,
    tests: Option<String>,
    job: Option<String>,
    redact: Option<String>,
    findings: Option<String>,
    frequency: Option<String>,
    categories: Option<String>,
}

impl ActionForm {
    /// A form built by a page that collects a list (checkboxes) before the
    /// confirmation step; `fields` are the same names a posted form carries.
    pub(crate) fn built(action: &str, csrf: &str, fields: &[(&str, String)]) -> Self {
        let mut form = Self {
            action: action.to_owned(),
            csrf: csrf.to_owned(),
            password: None,
            package: None,
            port: None,
            protocol: None,
            name: None,
            enabled: None,
            timezone: None,
            ntp: None,
            tests: None,
            job: None,
            redact: None,
            findings: None,
            frequency: None,
            categories: None,
        };
        for (field, value) in fields {
            let value = Some(value.clone());
            match *field {
                "job" => form.job = value,
                "findings" => form.findings = value,
                "categories" => form.categories = value,
                "tests" => form.tests = value,
                _ => {}
            }
        }
        form
    }

    /// Every variant checks that only its own parameters are present, so a
    /// forged form cannot smuggle extra fields into another operation.
    fn operation(&self) -> Option<Operation> {
        let no_extras = |allowed: &[&str]| {
            let present: &[(&str, bool)] = &[
                ("package", self.package.is_some()),
                ("port", self.port.is_some()),
                ("protocol", self.protocol.is_some()),
                ("name", self.name.is_some()),
                ("enabled", self.enabled.is_some()),
                ("timezone", self.timezone.is_some()),
                ("ntp", self.ntp.is_some()),
                ("tests", self.tests.is_some()),
                ("job", self.job.is_some()),
                ("redact", self.redact.is_some()),
                ("findings", self.findings.is_some()),
                ("frequency", self.frequency.is_some()),
                ("categories", self.categories.is_some()),
            ];
            present
                .iter()
                .all(|(field, is_present)| !is_present || allowed.contains(field))
        };
        let name = || self.name.as_deref();
        let enabled = || self.enabled.as_deref();
        let job = || self.job.as_deref();
        if let Some(key) = self.action.strip_prefix("read-") {
            return no_extras(&[])
                .then(|| ReadQuery::from_key(key))
                .flatten()
                .map(Operation::Read);
        }
        match self.action.as_str() {
            "install" if no_extras(&["package"]) => {
                Operation::install(self.package.as_deref()?).ok()
            }
            "remove" if no_extras(&["package"]) => Operation::remove(self.package.as_deref()?).ok(),
            "add-port" if no_extras(&["port", "protocol"]) => {
                Operation::port(self.port.as_deref()?, self.protocol.as_deref()?).ok()
            }
            "remove-port" if no_extras(&["port", "protocol"]) => {
                Operation::remove_port(self.port.as_deref()?, self.protocol.as_deref()?).ok()
            }
            "firewall-service" if no_extras(&["name", "enabled"]) => {
                Operation::firewall_service(name()?, enabled()?).ok()
            }
            "service-enabled" if no_extras(&["name", "enabled"]) => {
                Operation::service_enabled(name()?, enabled()?).ok()
            }
            "service-running" if no_extras(&["name", "enabled"]) => {
                Operation::service_running(name()?, enabled()?).ok()
            }
            "service-restart" if no_extras(&["name"]) => Operation::service_restart(name()?).ok(),
            "update-all" if no_extras(&[]) => Some(Operation::UpdateAllNative),
            "repo-enabled" if no_extras(&["name", "enabled"]) => {
                Operation::repo_enabled(name()?, enabled()?).ok()
            }
            "clear-cache" if no_extras(&[]) => Some(Operation::ClearNativeCache),
            "set-admin" if no_extras(&["name", "enabled"]) => {
                Operation::set_admin(name()?, enabled()?).ok()
            }
            "datetime" if no_extras(&["timezone", "ntp"]) => {
                Operation::datetime(self.timezone.as_deref()?, self.ntp.as_deref()?).ok()
            }
            "diagnostics-start" if no_extras(&["tests"]) => {
                Operation::diagnostics_start(self.tests.as_deref()?).ok()
            }
            "network-check" if no_extras(&[]) => Some(Operation::NetworkCheck),
            "diagnostics-report" if no_extras(&["job", "redact"]) => {
                Operation::diagnostics_report(job()?, self.redact.as_deref()?).ok()
            }
            "repair-findings" if no_extras(&["job", "findings"]) => {
                Operation::repair_findings(job()?, self.findings.as_deref()?).ok()
            }
            "mark-logs-seen" if no_extras(&["job"]) => Operation::mark_logs_seen(job()?).ok(),
            "set-periodic" if no_extras(&["enabled", "frequency"]) => {
                Operation::set_periodic(enabled()?, self.frequency.as_deref()?).ok()
            }
            "cleanup-clean" if no_extras(&["categories"]) => {
                Operation::cleanup_clean(self.categories.as_deref()?).ok()
            }
            _ => None,
        }
    }

    /// The hidden fields a confirmation page must carry so the same
    /// operation reaches `execute` unchanged.
    fn hidden_fields(&self) -> String {
        let mut fields = String::new();
        for (field, value) in [
            ("action", Some(self.action.as_str())),
            ("package", self.package.as_deref()),
            ("port", self.port.as_deref()),
            ("protocol", self.protocol.as_deref()),
            ("name", self.name.as_deref()),
            ("enabled", self.enabled.as_deref()),
            ("timezone", self.timezone.as_deref()),
            ("ntp", self.ntp.as_deref()),
            ("tests", self.tests.as_deref()),
            ("job", self.job.as_deref()),
            ("redact", self.redact.as_deref()),
            ("findings", self.findings.as_deref()),
            ("frequency", self.frequency.as_deref()),
            ("categories", self.categories.as_deref()),
        ] {
            if let Some(value) = value {
                fields.push_str(&format!(
                    r#"<input type="hidden" name="{field}" value="{}">"#,
                    html_escape(value)
                ));
            }
        }
        fields
    }
}

/// Step one of every administrative action: a page-level dialog that names
/// the operation and asks the password. It never touches the broker.
pub async fn confirm(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Form(form): Form<ActionForm>,
) -> Response {
    let username = user.name.clone();
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    if state.admin_socket.is_none() {
        return (
            StatusCode::FORBIDDEN,
            render(
                t(
                    "Ação indisponível",
                    "Action unavailable",
                    "Acción no disponible",
                ),
                "/",
                &user,
                super::unavailable_notice(lang),
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
    if lease.username != username || !matching_csrf(&lease.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, invalid_session(lang)).into_response();
    }
    let Some(operation) = form.operation() else {
        return (StatusCode::BAD_REQUEST, invalid_operation(lang)).into_response();
    };
    let body = format!(
        r#"<div class="dialog">
<div class="dialog-icon">{icon}</div>
<div>
<h2>{title}</h2>
<p class="dialog-summary">{summary}</p>
</div>
<form method="post" action="/administracao">
{hidden}<input type="hidden" name="csrf" value="{csrf}">
<div class="field"><label for="password">{your_password}</label>
<div class="field-input"><input id="password" type="password" name="password" autocomplete="current-password" autofocus required maxlength="4096"></div></div>
<p class="dialog-meta">{polkit} <code>{action}</code> · {runs_as} {username}</p>
<div class="dialog-actions"><a class="button-link" href="{back}">{cancel}</a><button type="submit">{confirm}</button></div>
</form>
</div>"#,
        icon = super::widgets::icon("firewall"),
        title = html_escape(&operation.describe_in(lang)),
        summary = t(
            "A operação é executada com a sua identidade e registrada no journal. Confirme com sua senha.",
            "The operation runs with your identity and is recorded in the journal. Confirm with your password.",
            "La operación se ejecuta con su identidad y queda registrada en el journal. Confirme con su contraseña.",
        ),
        your_password = t("Sua senha", "Your password", "Su contraseña"),
        polkit = t(
            "Autorização polkit",
            "polkit authorization",
            "Autorización polkit"
        ),
        runs_as = t("executa como", "runs as", "se ejecuta como"),
        cancel = t("Cancelar", "Cancel", "Cancelar"),
        confirm = t("Confirmar", "Confirm", "Confirmar"),
        hidden = form.hidden_fields(),
        csrf = html_escape(&lease.csrf),
        action = operation.action_id(),
        username = html_escape(&username),
        back = operation.return_href(),
    );
    render(
        t("Confirmar ação", "Confirm action", "Confirmar acción"),
        operation.return_href(),
        &user,
        body,
    )
    .into_response()
}

fn invalid_session(lang: vega_web::lang::Lang) -> &'static str {
    lang.text(
        "Confirmação de sessão inválida.",
        "Invalid session confirmation.",
        "Confirmación de sesión no válida.",
    )
}

fn invalid_operation(lang: vega_web::lang::Lang) -> &'static str {
    lang.text(
        "Operação ou parâmetros inválidos.",
        "Invalid operation or parameters.",
        "Operación o parámetros no válidos.",
    )
}

pub(crate) fn matching_csrf(expected: &str, received: &str) -> bool {
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
    Extension(user): Extension<CurrentUser>,
    Form(mut form): Form<ActionForm>,
) -> Response {
    let username = user.name.clone();
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    // Move the secret out before validation so every early return clears it.
    let password = Zeroizing::new(std::mem::take(&mut form.password).unwrap_or_default());
    let Some(path) = state.admin_socket.as_deref() else {
        return (
            StatusCode::FORBIDDEN,
            t(
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
            t("Sessão encerrada.", "Session closed.", "Sesión cerrada."),
        )
            .into_response();
    };
    if lease.username != username || !matching_csrf(&lease.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, invalid_session(lang)).into_response();
    }
    let Some(operation) = form.operation() else {
        return (StatusCode::BAD_REQUEST, invalid_operation(lang)).into_response();
    };
    if password.is_empty()
        || password.len() > vega_web::auth_ipc::MAX_PASSWORD
        || password.contains('\0')
    {
        return (
            StatusCode::BAD_REQUEST,
            t(
                "Senha necessária.",
                "Password required.",
                "Contraseña necesaria.",
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
            t(
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
            t(
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
    let pending_cleanup = if matches!(operation, Operation::CleanupClean(_)) {
        match super::diagnostics::prepare_cleanup(&state, lease.admin_binding, lang).await {
            Ok(pending) => Some(pending),
            Err(error) => {
                return (
                    StatusCode::CONFLICT,
                    render(
                        t("Liberar espaço", "Free up space", "Liberar espacio"),
                        "/armazenamento",
                        &user,
                        format!(r#"<p class="notice warn">{}</p>"#, html_escape(&error)),
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
            return (StatusCode::UNAUTHORIZED, t(
                "Sessão encerrada. Entre novamente e confira o estado da operação antes de repetir.",
                "Session closed. Sign in again and check the state of the operation before repeating it.",
                "Sesión cerrada. Vuelva a entrar y compruebe el estado de la operación antes de repetirla.",
            )).into_response();
        },
        result = admin_ipc::execute(Path::new(path), request) => result,
    };
    match outcome {
        Ok(result) => {
            state.login_limiter.success(&ip, &username);
            eprintln!("vega-web: id={} user={username:?} action={} transaction={} outcome=accepted",
                      result.audit_id, operation.action_id(), result.transaction);
            state
                .audit
                .record(&username, &ip, operation.describe());
            if let Some(pending) = pending_cleanup {
                return pending.accepted(result.transaction, lease);
            }
            if let Some(response) = super::diagnostics::accepted(
                &state,
                &jar,
                &user,
                &operation,
                result.transaction,
                &result.payload,
            ) {
                return response;
            }
            if let Operation::Read(query) = &operation {
                if let (Some(cookie), Ok(json)) = (
                    jar.get(SESSION_COOKIE),
                    String::from_utf8(result.payload.clone()),
                ) {
                    state.sessions.store_read(cookie.value(), query.key(), json);
                }
                return Redirect::to(query.return_href()).into_response();
            }
            if let Some(cookie) = jar.get(SESSION_COOKIE) {
                state.sessions.clear_reads(cookie.value());
            }
            let (status, message) = match &operation {
                Operation::InstallNative(name) => (StatusCode::ACCEPTED, format!(
                    "{} <strong>{}</strong> {}. {} {}. {}",
                    t("Solicitação de instalação de", "Installation request for", "Solicitud de instalación de"),
                    html_escape(name),
                    t("aceita", "accepted", "aceptada"),
                    t("Transação", "Transaction", "Transacción"),
                    result.transaction,
                    t(
                        "A instalação ainda precisa concluir; confira o estado do pacote antes de repetir.",
                        "The installation still has to finish; check the package state before repeating it.",
                        "La instalación todavía tiene que terminar; compruebe el estado del paquete antes de repetirla.",
                    ))),
                Operation::RemoveNative(name) => (StatusCode::ACCEPTED, format!(
                    "{} <strong>{}</strong> {}. {} {}.",
                    t("Remoção de", "Removal of", "Eliminación de"),
                    html_escape(name),
                    t("aceita", "accepted", "aceptada"),
                    t("Transação", "Transaction", "Transacción"),
                    result.transaction)),
                Operation::UpdateAllNative => (StatusCode::ACCEPTED, format!(
                    "{} {} {}. {}",
                    t("Aplicação das atualizações aceita.", "Update application accepted.", "Aplicación de las actualizaciones aceptada."),
                    t("Transação", "Transaction", "Transacción"),
                    result.transaction,
                    t("Acompanhe o estado em Software.", "Follow the state in Software.", "Siga el estado en Software."))),
                Operation::ClearNativeCache => (StatusCode::ACCEPTED, format!(
                    "{} {} {}.",
                    t("Limpeza do cache de pacotes aceita.", "Package cache cleanup accepted.", "Limpieza de la caché de paquetes aceptada."),
                    t("Transação", "Transaction", "Transacción"),
                    result.transaction)),
                other => (StatusCode::OK, format!(
                    "{}: {}.",
                    html_escape(&other.describe_in(lang)),
                    t("concluído", "done", "completado"))),
            };
            let back = operation.return_href();
            (status, render(t("Ação concluída", "Action completed", "Acción completada"), back, &user,
                format!(r#"<p class="notice success">{message}</p><p><a class="button-link" href="{back}">{}</a></p>"#,
                    t("Voltar", "Back", "Volver")))).into_response()
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let delay = state.login_limiter.failure(&ip, &username, Instant::now());
            tokio::time::sleep(delay).await;
            (StatusCode::FORBIDDEN, t(
                "Operação não autorizada. Verifique suas credenciais e permissões.",
                "Operation not authorized. Check your credentials and permissions.",
                "Operación no autorizada. Compruebe sus credenciales y permisos.",
            )).into_response()
        }
        Err(_) => (StatusCode::BAD_GATEWAY,
            t(
                "Não foi possível confirmar o resultado. Confira o estado da operação antes de repetir.",
                "The result could not be confirmed. Check the state of the operation before repeating it.",
                "No se pudo confirmar el resultado. Compruebe el estado de la operación antes de repetirla.",
            )).into_response(),
    }
}
