use axum::Form;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use rand::RngExt;
use serde::Deserialize;

use crate::layout::login_page;
use crate::pam_ffi;
use crate::state::{AppState, SESSION_COOKIE, Session};

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
        .and_then(|cookie| state.sessions.username_for(cookie.value()));

    match username {
        Some(username) => {
            req.extensions_mut().insert(CurrentUser(username));
            next.run(req).await
        }
        None => Redirect::to("/login").into_response(),
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
    jar: PrivateCookieJar,
    Form(form): Form<LoginRequest>,
) -> Response {
    let username = form.username.trim().to_string();
    if username.is_empty() || form.password.is_empty() {
        return Html(login_page(Some("Usuário e senha são obrigatórios."))).into_response();
    }

    let service = state.pam_service.clone();
    let auth_username = username.clone();
    let password = form.password.clone();
    let result = tokio::task::spawn_blocking(move || {
        pam_ffi::authenticate(&service, &auth_username, &password)
    })
    .await
    .expect("thread de autenticação PAM não deve entrar em pânico");

    match result {
        Ok(()) => {
            let token = new_session_token();
            state.sessions.insert(token.clone(), Session { username });
            let cookie = Cookie::build((SESSION_COOKIE, token))
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Strict)
                .path("/")
                .build();
            (jar.add(cookie), Redirect::to("/")).into_response()
        }
        Err(_) => Html(login_page(Some("Usuário ou senha inválidos."))).into_response(),
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
