use std::net::SocketAddr;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Form};
use axum_extra::extract::cookie::PrivateCookieJar;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::auth::CurrentUser;
use crate::state::{AppState, SESSION_COOKIE, SessionLease};

use super::render;

const XTERM_JS: &str = include_str!("../../assets/xterm/xterm.js");
const XTERM_CSS: &str = include_str!("../../assets/xterm/xterm.css");

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let token = jar
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default();
    if !state.terminal_grants.valid(&token, Instant::now()) {
        let body = r#"<p>Por segurança, confirme sua senha antes de abrir um shell completo.</p>
<form method="post" action="/terminal">
<label>Senha<br><input type="password" name="password" autocomplete="current-password" required autofocus></label>
<button type="submit">Abrir terminal</button>
</form>"#;
        return render("Terminal", "/terminal", &user, body.to_string()).into_response();
    }
    let body = r#"
<p>Shell completo do servidor. O acesso é permitido somente a administradores do grupo <code>wheel</code>.</p>
<div id="terminal-status" class="badge">Conectando…</div>
<div id="terminal" aria-label="Terminal do servidor"></div>
<style>
.content { max-width: none; }
#terminal { height: calc(100vh - 13rem); min-height: 28rem; margin-top: 1rem; padding: .65rem;
  background: #0b0d12; border: 1px solid var(--border); border-radius: var(--radius-md); }
#terminal .xterm { height: 100%; }
</style>
<link rel="stylesheet" href="/assets/xterm.css">
<script src="/assets/xterm.js"></script>
<script>
(() => {
  const host = document.getElementById('terminal');
  const status = document.getElementById('terminal-status');
  const terminal = new Terminal({
    cursorBlink: true, convertEol: false, scrollback: 5000,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: 14,
    theme: { background: '#0b0d12', foreground: '#e6e9ef', cursor: '#a78bfa' }
  });
  terminal.open(host);

  let socket;
  const resize = () => {
    const cols = Math.max(20, Math.floor(host.clientWidth / 8.45));
    const rows = Math.max(5, Math.floor(host.clientHeight / 17));
    terminal.resize(cols, rows);
    if (socket?.readyState === WebSocket.OPEN)
      socket.send(JSON.stringify({type: 'resize', cols, rows}));
  };
  resize();
  new ResizeObserver(resize).observe(host);

  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${scheme}//${location.host}/terminal/ws`);
  socket.binaryType = 'arraybuffer';
  socket.onopen = () => { status.textContent = 'Conectado'; status.classList.add('on'); resize(); terminal.focus(); };
  socket.onmessage = event => terminal.write(typeof event.data === 'string' ? event.data : new Uint8Array(event.data));
  socket.onclose = event => { status.textContent = event.reason || 'Sessão encerrada'; status.classList.remove('on'); terminal.write('\r\n\x1b[31m[Sessão encerrada]\x1b[0m\r\n'); };
  socket.onerror = () => { status.textContent = 'Falha na conexão'; };
  terminal.onData(data => { if (socket.readyState === WebSocket.OPEN) socket.send(new TextEncoder().encode(data)); });
})();
</script>"#;
    render("Terminal", "/terminal", &user, body.to_string()).into_response()
}

#[derive(Deserialize)]
pub struct ReauthRequest {
    password: String,
}

pub async fn reauthenticate(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
    Form(form): Form<ReauthRequest>,
) -> Response {
    let username = user.name.clone();
    let token = match jar.get(SESSION_COOKIE) {
        Some(cookie) => cookie.value().to_string(),
        None => return Redirect::to("/login").into_response(),
    };
    let ip = remote.ip().to_string();
    if state
        .login_limiter
        .check(&ip, &username, Instant::now())
        .is_some()
    {
        return (StatusCode::TOO_MANY_REQUESTS, "muitas tentativas; aguarde").into_response();
    }
    let permit = match state.pam_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "autenticação ocupada").into_response();
        }
    };
    let password = zeroize::Zeroizing::new(form.password);
    // The root helper checks the password with PAM itself (vega-web#34);
    // this process keeps the authenticated connection, never the password.
    let result = open_authenticated(&state.terminal_socket, &username, &password).await;
    drop(permit);
    if let Ok(helper) = result {
        state.login_limiter.success(&ip, &username);
        state.terminal_grants.grant(
            token,
            Instant::now() + Duration::from_secs(60),
            Some(helper),
        );
        Redirect::to("/terminal").into_response()
    } else {
        let delay = state.login_limiter.failure(&ip, &username, Instant::now());
        tokio::time::sleep(delay).await;
        let body = r#"<p class="error">Senha inválida.</p><p>O terminal não foi aberto.</p>
<form method="post" action="/terminal"><label>Senha<br><input type="password" name="password" autocomplete="current-password" required autofocus></label><button type="submit">Tentar novamente</button></form>"#;
        render("Terminal", "/terminal", &user, body.to_string()).into_response()
    }
}

pub async fn websocket(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "origem WebSocket inválida").into_response();
    }
    let token = jar
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default();
    let Some(Some(helper)) = state.terminal_grants.consume(&token, Instant::now()) else {
        return (StatusCode::FORBIDDEN, "reautenticação necessária").into_response();
    };
    let Some(lease) = state.sessions.lease(&token, Instant::now()) else {
        return (StatusCode::UNAUTHORIZED, "sessão encerrada").into_response();
    };
    let permit = match state.terminal_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "limite de terminais atingido",
            )
                .into_response();
        }
    };
    ws.max_message_size(64 * 1024)
        .on_upgrade(move |socket| run_terminal(socket, lease, permit, helper))
}

async fn run_terminal(
    mut socket: WebSocket,
    mut lease: SessionLease,
    _permit: tokio::sync::OwnedSemaphorePermit,
    helper: UnixStream,
) {
    // Cancel the entire bridge, including connect and blocked writes. Merely
    // selecting on revocation inside the read loop would leave those awaits
    // alive after logout. Dropping the bridge closes both helper socket halves.
    let revoked = tokio::select! {
        biased;
        _ = lease.revoked() => true,
        _ = bridge_terminal(&mut socket, helper) => false,
    };
    let frame = CloseFrame {
        code: if revoked {
            close_code::POLICY
        } else {
            close_code::NORMAL
        },
        reason: "Sessão encerrada".into(),
    };
    let _ = tokio::time::timeout(
        Duration::from_millis(250),
        socket.send(Message::Close(Some(frame))),
    )
    .await;
}

async fn bridge_terminal(socket: &mut WebSocket, stream: UnixStream) {
    let (mut output, mut input) = stream.into_split();
    // The helper authenticated the user at reauthentication and waits for
    // this byte before opening the shell.
    if input.write_all(b"G").await.is_err() {
        return;
    }
    let mut buffer = [0_u8; 8192];

    loop {
        tokio::select! {
            message = socket.recv() => match message {
                Some(Ok(Message::Binary(data))) if !data.is_empty() => {
                    if write_input(&mut input, &data).await.is_err() { break; }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Some((cols, rows)) = parse_resize(&text)
                        && write_resize(&mut input, cols, rows).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
            read = output.read(&mut buffer) => match read {
                Ok(0) | Err(_) => break,
                Ok(count) => if socket.send(Message::Binary(buffer[..count].to_vec().into())).await.is_err() { break; },
            }
        }
    }
    drop(input);
}

fn same_origin(headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    origin == format!("https://{host}")
}

/// Opens a helper connection and sends the credentials frame (`A`, u16
/// length + user, u16 length + password). The helper answers 0 when PAM
/// accepted the password and the user may open a terminal.
async fn open_authenticated(
    socket_path: &str,
    username: &str,
    password: &str,
) -> std::io::Result<UnixStream> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "credenciais recusadas",
        )
    };
    let (user, secret) = (username.as_bytes(), password.as_bytes());
    if user.is_empty() || user.len() > 256 || secret.is_empty() || secret.len() > 4096 {
        return Err(invalid());
    }
    let mut frame = zeroize::Zeroizing::new(Vec::with_capacity(5 + user.len() + secret.len()));
    frame.push(b'A');
    frame.extend_from_slice(&(user.len() as u16).to_be_bytes());
    frame.extend_from_slice(user);
    frame.extend_from_slice(&(secret.len() as u16).to_be_bytes());
    frame.extend_from_slice(secret);
    let mut stream = UnixStream::connect(socket_path).await?;
    stream.write_all(&frame).await?;
    let mut answer = [1_u8; 1];
    match tokio::time::timeout(Duration::from_secs(35), stream.read_exact(&mut answer)).await {
        Ok(Ok(_)) if answer[0] == 0 => Ok(stream),
        _ => Err(invalid()),
    }
}

async fn write_input(
    input: &mut tokio::net::unix::OwnedWriteHalf,
    data: &[u8],
) -> std::io::Result<()> {
    input.write_all(b"I").await?;
    input.write_all(&(data.len() as u32).to_be_bytes()).await?;
    input.write_all(data).await
}

async fn write_resize(
    input: &mut tokio::net::unix::OwnedWriteHalf,
    cols: u16,
    rows: u16,
) -> std::io::Result<()> {
    input.write_all(b"R").await?;
    input.write_all(&cols.to_be_bytes()).await?;
    input.write_all(&rows.to_be_bytes()).await
}

fn parse_resize(value: &str) -> Option<(u16, u16)> {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.contains("\"type\":\"resize\"") {
        return None;
    }
    fn number_after(value: &str, key: &str) -> Option<u16> {
        let tail = value.split(key).nth(1)?;
        tail.trim_start_matches(':')
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    }
    let cols = number_after(&compact, "\"cols\"")?.clamp(20, 500);
    let rows = number_after(&compact, "\"rows\"")?.clamp(5, 300);
    Some((cols, rows))
}

pub async fn xterm_js() -> Response {
    asset("text/javascript; charset=utf-8", XTERM_JS)
}
pub async fn xterm_css() -> Response {
    asset("text/css; charset=utf-8", XTERM_CSS)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}

#[cfg(test)]
#[path = "terminal_session_tests.rs"]
mod session_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resize_is_bounded_and_rejects_other_messages() {
        assert_eq!(
            parse_resize(r#"{"type":"resize","cols":120,"rows":40}"#),
            Some((120, 40))
        );
        assert_eq!(
            parse_resize(r#"{"type":"resize","cols":9999,"rows":1}"#),
            Some((500, 5))
        );
        assert_eq!(
            parse_resize(r#"{"type":"input","cols":80,"rows":24}"#),
            None
        );
    }

    #[test]
    fn websocket_origin_must_match_host_and_https() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("server.local:9090"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://server.local:9090"),
        );
        assert!(same_origin(&headers));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!same_origin(&headers));
    }
}
