mod auth;
mod layout;
mod pages;
mod pam_ffi;
mod state;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::routing::{get, post};
use axum::{Router, middleware};
use axum_extra::extract::cookie::Key;

use state::{AppState, SessionStore};

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
    let tls_names: Vec<String> = env_or("VEGA_WEB_TLS_NAMES", "localhost")
        .split(',')
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();

    let dbus = lyra_vega_dbus::VegaDbus::connect()
        .await
        .expect("não foi possível conectar ao system bus (vegad precisa estar instalado)");

    let state = AppState {
        dbus,
        sessions: SessionStore::default(),
        cookie_key: Key::generate(),
        pam_service,
    };

    let tls_config = tls::ensure_self_signed(&tls_dir, &tls_names)
        .await
        .expect("não foi possível preparar o certificado TLS");

    let protected = Router::new()
        .route("/", get(pages::dashboard::handler))
        .route("/software", get(pages::software::handler))
        .route("/backup", get(pages::backup::handler))
        .route("/snapshots", get(pages::snapshots::handler))
        .route("/hardware", get(pages::hardware::handler))
        .route("/armazenamento", get(pages::storage::handler))
        .route("/rede", get(pages::network::handler))
        .route("/bluetooth", get(pages::bluetooth::handler))
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
        .serve(app.into_make_service())
        .await
        .expect("falha ao servir HTTPS");
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
