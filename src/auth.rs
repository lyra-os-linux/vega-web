use axum::Form;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use rand::RngExt;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::layout::login_page;
use crate::pam_ffi;
use crate::state::{AppState, SESSION_COOKIE, Session};

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, username: &str, password: &str) -> Result<(), String>;
}

pub struct PamAuthenticator {
    service: String,
}

impl PamAuthenticator {
    pub fn new(service: String) -> Self {
        Self { service }
    }
}

impl Authenticator for PamAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> Result<(), String> {
        pam_ffi::authenticate(&self.service, username, password)
            .map_err(|error| format!("{error:?}"))
    }
}

/// Extractor injetado pelo middleware `require_session` nas rotas
/// protegidas: se um handler o recebe, a sessão já foi validada.
#[derive(Clone)]
pub struct CurrentUser(pub String);

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
            req.extensions_mut().insert(CurrentUser(username));
            next.run(req).await
        }
        None => (
            jar.remove(Cookie::from(SESSION_COOKIE)),
            Redirect::to("/login"),
        )
            .into_response(),
    }
}

pub async fn login_form() -> Html<String> {
    Html(login_page(None))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    jar: PrivateCookieJar,
    Form(form): Form<LoginRequest>,
) -> Response {
    let username = form.username.trim().to_string();
    if username.is_empty() || form.password.is_empty() {
        return Html(login_page(Some("Usuário e senha são obrigatórios."))).into_response();
    }

    let ip = remote.ip().to_string();
    let now = Instant::now();
    if let Some(wait) = state.login_limiter.check(&ip, &username, now) {
        eprintln!(
            "vega-web: login bloqueado ip={ip} usuário={username} espera={}s",
            wait.as_secs().max(1)
        );
        return Html(login_page(Some(
            "Muitas tentativas. Aguarde antes de tentar novamente.",
        )))
        .into_response();
    }

    let permit = match state.pam_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            eprintln!(
                "vega-web: login recusado por limite de autenticações simultâneas ip={ip} usuário={username}"
            );
            return Html(login_page(Some(
                "Servidor de autenticação ocupado. Tente novamente.",
            )))
            .into_response();
        }
    };
    let result = run_authentication(
        Arc::clone(&state.authenticator),
        username.clone(),
        form.password.clone(),
        permit,
    )
    .await;

    match result {
        Ok(Ok(())) => {
            state.login_limiter.success(&ip, &username);
            eprintln!("vega-web: login bem-sucedido ip={ip} usuário={username}");
            let token = new_session_token();
            state
                .sessions
                .insert(token.clone(), Session::new(username, Instant::now()));
            let cookie = session_cookie(token);
            (jar.add(cookie), Redirect::to("/")).into_response()
        }
        Ok(Err(_)) => {
            let delay = state.login_limiter.failure(&ip, &username, Instant::now());
            eprintln!("vega-web: login falhou ip={ip} usuário={username}");
            tokio::time::sleep(delay).await;
            Html(login_page(Some("Usuário ou senha inválidos."))).into_response()
        }
        Err(error) => {
            let delay = state.login_limiter.failure(&ip, &username, Instant::now());
            eprintln!("vega-web: tarefa PAM falhou ip={ip} usuário={username}: {error}");
            tokio::time::sleep(delay).await;
            Html(login_page(Some("Falha temporária na autenticação."))).into_response()
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
