mod auth;
mod layout;
mod pages;
mod pam_ffi;
mod state;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::{Router, middleware};
use axum_extra::extract::cookie::Key;

use auth::PamAuthenticator;
use state::{AppState, LoginLimiter, LoginPolicy, SessionPolicy, SessionStore};
use tokio::sync::Semaphore;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("provider TLS já instalado ou indisponível");

    let bind_addr: SocketAddr = env_or("VEGA_WEB_BIND", "0.0.0.0:9090")
        .parse()
        .expect("VEGA_WEB_BIND deve ser um endereço host:porta válido");
    let tls_dir = PathBuf::from(env_or("VEGA_WEB_TLS_DIR", "/etc/vega/web/tls"));
    let pam_service = env_or("VEGA_WEB_PAM_SERVICE", "vega-web");
    let default_tls_names = default_tls_names(bind_addr);
    let tls_names: Vec<String> = env_or("VEGA_WEB_TLS_NAMES", &default_tls_names)
        .split(',')
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();

    let dbus = lyra_vega_dbus::VegaDbus::connect()
        .await
        .expect("não foi possível conectar ao system bus (vegad precisa estar instalado)");

    let state = AppState {
        dbus,
        sessions: SessionStore::new(SessionPolicy {
            idle_timeout: Duration::from_secs(env_u64("VEGA_WEB_SESSION_IDLE_SECS", 1800)),
            absolute_timeout: Duration::from_secs(env_u64("VEGA_WEB_SESSION_MAX_SECS", 43200)),
            global_limit: env_usize("VEGA_WEB_SESSION_GLOBAL_LIMIT", 1024),
            per_user_limit: env_usize("VEGA_WEB_SESSION_USER_LIMIT", 10),
        }),
        cookie_key: Key::generate(),
        authenticator: Arc::new(PamAuthenticator::new(pam_service)),
        login_limiter: LoginLimiter::new(LoginPolicy {
            attempts: env_u64("VEGA_WEB_LOGIN_ATTEMPTS", 5) as u32,
            recovery: Duration::from_secs(env_u64("VEGA_WEB_LOGIN_RECOVERY_SECS", 900)),
            base_delay: Duration::from_millis(env_u64("VEGA_WEB_LOGIN_DELAY_MS", 500)),
            max_delay: Duration::from_secs(env_u64("VEGA_WEB_LOGIN_MAX_DELAY_SECS", 30)),
        }),
        pam_slots: Arc::new(Semaphore::new(env_usize("VEGA_WEB_PAM_CONCURRENCY", 4))),
    };

    let tls_config = tls::ensure_self_signed(
        &tls_dir,
        &tls_names,
        env_or("VEGA_WEB_TLS_EXTERNAL", "false").eq_ignore_ascii_case("true"),
    )
    .await
    .expect("não foi possível preparar o certificado TLS");

    let protected = Router::new()
        .route("/", get(pages::dashboard::handler))
        .route(
            "/software",
            get(pages::software::handler).post(pages::software::install_native),
        )
        .route("/backup", get(pages::backup::handler))
        .route("/snapshots", get(pages::snapshots::handler))
        .route("/hardware", get(pages::hardware::handler))
        .route("/armazenamento", get(pages::storage::handler))
        .route(
            "/rede",
            get(pages::network::handler).post(pages::network::add_firewall_rule),
        )
        .route("/servicos", get(pages::services::handler))
        .route("/usuarios", get(pages::users::handler))
        .route("/logs", get(pages::logs::handler))
        .route("/monitor", get(pages::monitor::handler))
        .route("/data-hora", get(pages::datetime::handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));

    let app = protected
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route("/logout", post(auth::logout))
        .with_state(state);

    eprintln!("vega-web: ouvindo em https://{bind_addr}");
    axum_server::bind_rustls(bind_addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("falha ao servir HTTPS");
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn default_tls_names(bind_addr: SocketAddr) -> String {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let hostname = hostname.trim();
        if !hostname.is_empty() {
            names.push(hostname.to_string());
        }
    }
    if !bind_addr.ip().is_unspecified() {
        names.push(bind_addr.ip().to_string());
    }
    names.join(",")
}
