use super::*;
use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, Key};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};

use crate::auth::{self, Authenticator};
use crate::state::{
    LoginLimiter, LoginPolicy, Session, SessionPolicy, SessionStore, TerminalGrants,
};

struct UnusedAuthenticator;
impl Authenticator for UnusedAuthenticator {
    fn authenticate(&self, _: &str, _: &str) -> Result<(), String> {
        panic!("these tests seed sessions; PAM must not run");
    }
}

fn cookie_header(key: &Key, token: &str) -> String {
    let response = PrivateCookieJar::new(key.clone())
        .add(Cookie::new(SESSION_COOKIE, token.to_string()))
        .into_response();
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn connect(
    address: SocketAddr,
    cookie: &str,
) -> Result<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Error> {
    let mut request = format!("ws://{address}/terminal/ws").into_client_request()?;
    request
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    request.headers_mut().insert(
        header::ORIGIN,
        format!("https://{address}").parse().unwrap(),
    );
    let stream = TcpStream::connect(address).await?;
    tokio_tungstenite::client_async(request, stream)
        .await
        .map(|(socket, _)| socket)
}

async fn logout_from_another_tab(address: SocketAddr, cookie: &str) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!(
        "POST /logout HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 303"));
}

#[tokio::test]
#[ignore = "requires a private D-Bus: bash scripts/check-session-contracts.sh"]
async fn session_integration_logout_expiry_and_backpressure() {
    for scenario in ["logout", "idle", "absolute", "blocked-input"] {
        tokio::time::timeout(Duration::from_secs(15), exercise_session(scenario))
            .await
            .expect(scenario);
    }
}

async fn exercise_session(scenario: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("terminal.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let key = Key::generate();
    let sessions = SessionStore::new(SessionPolicy {
        idle_timeout: Duration::from_secs(if scenario == "idle" { 2 } else { 20 }),
        absolute_timeout: Duration::from_secs(if scenario == "absolute" { 2 } else { 30 }),
        ..SessionPolicy::default()
    });
    let slots = Arc::new(Semaphore::new(1));
    let grants = TerminalGrants::default();
    let state = AppState {
        dbus: lyra_vega_dbus::VegaDbus::connect().await.unwrap(),
        sessions: sessions.clone(),
        cookie_key: key.clone(),
        authenticator: Arc::new(UnusedAuthenticator),
        login_limiter: LoginLimiter::new(LoginPolicy::default()),
        pam_slots: Arc::new(Semaphore::new(1)),
        terminal_grants: grants.clone(),
        terminal_slots: slots.clone(),
        terminal_socket: path.to_str().unwrap().into(),
    };
    let router = Router::new()
        .route("/terminal/ws", get(websocket))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ))
        .route("/logout", post(auth::logout))
        .with_state(state);
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(tcp, router).await.unwrap();
    });
    sessions.insert("token".into(), Session::new("alice".into(), Instant::now()));
    grants.grant("token".into(), Instant::now() + Duration::from_secs(60));
    let cookie = cookie_header(&key, "token");
    let (start_drain, drain) = tokio::sync::oneshot::channel();
    let helper = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'U');
        let length = stream.read_u16().await.unwrap();
        let mut user = vec![0; length as usize];
        stream.read_exact(&mut user).await.unwrap();
        assert_eq!(user, b"alice");
        stream.write_all(b"ready\n").await.unwrap();
        // Wait to drain until after revocation to exercise blocked IPC writes.
        let _ = drain.await;
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
    });
    let mut socket = connect(address, &cookie).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_data(),
        b"ready\n"[..]
    );
    assert_eq!(slots.available_permits(), 0);

    // Even a still-valid HTTP session cannot reuse the consumed terminal grant.
    let error = connect(address, &cookie).await.unwrap_err();
    assert!(
        matches!(error, tungstenite::Error::Http(response) if response.status() == StatusCode::FORBIDDEN)
    );

    let (mut writer, mut reader) = socket.split();
    let flood = if scenario == "blocked-input" {
        Some(tokio::spawn(async move {
            loop {
                if writer
                    .send(tungstenite::Message::Binary(vec![b'x'; 64 * 1024].into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }))
    } else {
        None
    };
    let activity = if scenario == "absolute" {
        let store = sessions.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if store.username_for("token", Instant::now()).is_none() {
                    break;
                }
            }
        }))
    } else {
        None
    };

    if scenario == "logout" || scenario == "blocked-input" {
        if scenario == "blocked-input" {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        logout_from_another_tab(address, &cookie).await;
    }
    // The terminal closes while its client socket is still open. Expiry does
    // not depend on a subsequent HTTP request cleaning the session store.
    let closed = reader.next().await.unwrap().unwrap();
    assert!(
        matches!(closed, tungstenite::Message::Close(Some(ref frame)) if frame.code == tungstenite::protocol::frame::coding::CloseCode::Policy),
        "{scenario}: {closed:?}"
    );
    start_drain.send(()).unwrap();
    helper.await.unwrap(); // EOF proves both helper socket halves were dropped.
    while slots.available_permits() != 1 {
        tokio::task::yield_now().await;
    }
    assert!(sessions.lease("token", Instant::now()).is_none());
    let error = connect(address, &cookie).await.unwrap_err();
    assert!(
        matches!(error, tungstenite::Error::Http(response) if response.status() == StatusCode::SEE_OTHER)
    );

    // A new login still needs a fresh terminal reauthentication grant.
    sessions.insert("new".into(), Session::new("alice".into(), Instant::now()));
    let error = connect(address, &cookie_header(&key, "new"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, tungstenite::Error::Http(response) if response.status() == StatusCode::FORBIDDEN)
    );
    if let Some(task) = flood {
        task.abort();
    }
    if let Some(task) = activity {
        task.abort();
    }
    server.abort();
    println!("session integration {scenario}: PASS");
}
