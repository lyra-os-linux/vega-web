use axum::Form;
use axum::extract::{ConnectInfo, RawQuery, Request, State};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use rand::RngExt;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::layout::login_page;
use crate::state::{AppState, SESSION_COOKIE, Session};

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, username: &str, password: &str) -> Result<(), String>;
}

pub struct PamAuthenticator {
    socket: std::path::PathBuf,
}

impl PamAuthenticator {
    pub fn new(socket: String) -> Self {
        Self {
            socket: socket.into(),
        }
    }
}

impl Authenticator for PamAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> Result<(), String> {
        vega_web::auth_ipc::authenticate(&self.socket, username, password)
            .map_err(|_| "authentication unavailable or rejected".into())
    }
}

/// Extractor injetado pelo middleware `require_session` nas rotas
/// protegidas: se um handler o recebe, a sessão já foi validada.
/// The authenticated viewer of a page: account name and the address the
/// session came from (shown in the sidebar and recorded in the activity log).
#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub name: String,
    pub address: String,
}

pub async fn require_session(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    let username = jar
        .get(SESSION_COOKIE)
        .and_then(|cookie| state.sessions.username_for(cookie.value(), Instant::now()));

    match username {
        Some(username) => {
            let address = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip().to_string())
                .unwrap_or_default();
            req.extensions_mut().insert(CurrentUser {
                name: username,
                address,
            });
            next.run(req).await
        }
        None => (
            jar.remove(Cookie::from(SESSION_COOKIE)),
            Redirect::to("/login"),
        )
            .into_response(),
    }
}

/// Language of the login page, chosen with `?lang=` and carried by the form.
/// The panel itself keeps its single language; this only covers the page a
/// visitor sees before authenticating.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoginLang {
    Pt,
    En,
    Es,
}

impl LoginLang {
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("en" | "en-US") => Self::En,
            Some("es" | "es-ES") => Self::Es,
            _ => Self::Pt,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::Pt => "pt-BR",
            Self::En => "en-US",
            Self::Es => "es-ES",
        }
    }

    pub fn text<'a>(self, pt: &'a str, en: &'a str, es: &'a str) -> &'a str {
        match self {
            Self::Pt => pt,
            Self::En => en,
            Self::Es => es,
        }
    }
}

/// `?lang=` on the login page; any other or malformed query is ignored.
fn query_lang(query: Option<&str>) -> LoginLang {
    let value = query
        .unwrap_or_default()
        .split('&')
        .find_map(|pair| pair.strip_prefix("lang="));
    LoginLang::parse(value)
}

pub async fn login_form(RawQuery(query): RawQuery) -> Html<String> {
    Html(login_page(
        None,
        query_lang(query.as_deref()),
        &crate::host::identity(),
    ))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
    lang: Option<String>,
}

fn login_error(lang: LoginLang, pt: &str, en: &str, es: &str) -> Response {
    Html(login_page(
        Some(lang.text(pt, en, es)),
        lang,
        &crate::host::identity(),
    ))
    .into_response()
}

pub async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    jar: PrivateCookieJar,
    Form(form): Form<LoginRequest>,
) -> Response {
    let lang = LoginLang::parse(form.lang.as_deref());
    let username = form.username.trim().to_string();
    if username.is_empty() || form.password.is_empty() {
        return login_error(
            lang,
            "Usuário e senha são obrigatórios.",
            "Username and password are required.",
            "Usuario y contraseña son obligatorios.",
        );
    }

    let ip = remote.ip().to_string();
    let now = Instant::now();
    if let Some(wait) = state.login_limiter.check(&ip, &username, now) {
        eprintln!(
            "vega-web: login bloqueado ip={ip} usuário={username:?} espera={}s",
            wait.as_secs().max(1)
        );
        return login_error(
            lang,
            "Muitas tentativas. Aguarde antes de tentar novamente.",
            "Too many attempts. Wait before trying again.",
            "Demasiados intentos. Espere antes de volver a intentarlo.",
        );
    }

    let permit = match state.pam_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            eprintln!(
                "vega-web: login recusado por limite de autenticações simultâneas ip={ip} usuário={username:?}"
            );
            return login_error(
                lang,
                "Servidor de autenticação ocupado. Tente novamente.",
                "Authentication service busy. Try again.",
                "Servicio de autenticación ocupado. Inténtelo de nuevo.",
            );
        }
    };
    let result = run_authentication(
        Arc::clone(&state.authenticator),
        username.clone(),
        form.password,
        permit,
    )
    .await;

    match result {
        Ok(Ok(())) => {
            state.login_limiter.success(&ip, &username);
            eprintln!("vega-web: login bem-sucedido ip={ip} usuário={username:?}");
            state.audit.record(&username, &ip, "Entrada no painel");
            let token = new_session_token();
            state
                .sessions
                .insert(token.clone(), Session::new(username, Instant::now()));
            let cookie = session_cookie(token);
            (jar.add(cookie), Redirect::to("/")).into_response()
        }
        Ok(Err(_)) => {
            let delay = state.login_limiter.failure(&ip, &username, Instant::now());
            eprintln!("vega-web: login falhou ip={ip} usuário={username:?}");
            tokio::time::sleep(delay).await;
            login_error(
                lang,
                "Usuário ou senha inválidos.",
                "Invalid username or password.",
                "Usuario o contraseña inválidos.",
            )
        }
        Err(error) => {
            let delay = state.login_limiter.failure(&ip, &username, Instant::now());
            eprintln!("vega-web: tarefa PAM falhou ip={ip} usuário={username:?}: {error}");
            tokio::time::sleep(delay).await;
            login_error(
                lang,
                "Falha temporária na autenticação.",
                "Temporary authentication failure.",
                "Fallo temporal de autenticación.",
            )
        }
    }
}

pub async fn logout(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        state.sessions.remove(cookie.value());
    }
    (
        jar.remove(Cookie::from(SESSION_COOKIE)),
        Redirect::to("/login"),
    )
        .into_response()
}

fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build()
}

async fn run_authentication(
    authenticator: Arc<dyn Authenticator>,
    username: String,
    password: String,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Result<(), String>, tokio::task::JoinError> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let password = zeroize::Zeroizing::new(password);
        authenticator.authenticate(&username, &password)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    struct FakeAuthenticator;
    struct PanicAuthenticator;

    impl Authenticator for FakeAuthenticator {
        fn authenticate(&self, username: &str, password: &str) -> Result<(), String> {
            if username == "alice" && password == "correct" {
                Ok(())
            } else {
                Err("invalid".into())
            }
        }
    }

    impl Authenticator for PanicAuthenticator {
        fn authenticate(&self, _: &str, _: &str) -> Result<(), String> {
            panic!("simulated PAM panic")
        }
    }

    #[test]
    fn session_cookie_is_hardened() {
        let cookie = session_cookie("token".into());
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
    }

    #[tokio::test]
    async fn replaceable_backend_covers_valid_and_invalid_login() {
        let backend: Arc<dyn Authenticator> = Arc::new(FakeAuthenticator);
        let semaphore = Arc::new(Semaphore::new(1));
        let valid = run_authentication(
            Arc::clone(&backend),
            "alice".into(),
            "correct".into(),
            semaphore.clone().acquire_owned().await.unwrap(),
        )
        .await
        .unwrap();
        assert!(valid.is_ok());
        let invalid = run_authentication(
            backend,
            "alice".into(),
            "wrong".into(),
            semaphore.acquire_owned().await.unwrap(),
        )
        .await
        .unwrap();
        assert!(invalid.is_err());
    }

    #[tokio::test]
    async fn backend_panic_is_contained_in_blocking_task() {
        let semaphore = Arc::new(Semaphore::new(1));
        let result = run_authentication(
            Arc::new(PanicAuthenticator),
            "alice".into(),
            "secret".into(),
            semaphore.acquire_owned().await.unwrap(),
        )
        .await;
        assert!(result.is_err());
    }
}
