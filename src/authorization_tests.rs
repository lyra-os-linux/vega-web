//! Exercise the production router against a permissive fake daemon. No host
//! PAM, Polkit or package/firewall changes are involved.
use super::*;
use axum::http::header;
use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar};
use lyra_vega_dbus::{FirewallClient, SoftwareClient};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type PackageRow = (String, String, String, String, bool, String, String);

struct Software(Arc<AtomicUsize>);

#[zbus::interface(name = "org.lyraos.Vega1.Software")]
impl Software {
    fn package_manager_name(&self) -> &str {
        "Zypper"
    }

    fn search_native(&self, query: &str) -> Vec<PackageRow> {
        vec![(
            "official".into(),
            query.into(),
            "Test package".into(),
            "Test description".into(),
            false,
            String::new(),
            "Test repository".into(),
        )]
    }

    fn list_native_updates(&self) -> Vec<PackageRow> {
        Vec::new()
    }

    fn list_repos(&self) -> Vec<(String, bool)> {
        vec![("Test repository".into(), true)]
    }

    fn install(&self, _origin: &str, _id: &str) -> u32 {
        self.0.fetch_add(1, Ordering::SeqCst);
        1
    }
}

struct Firewall(Arc<AtomicUsize>);

#[zbus::interface(name = "org.lyraos.Vega1.Firewall")]
impl Firewall {
    fn status(&self) -> (bool, String) {
        (true, "public".into())
    }

    fn list_services(&self) -> Vec<(String, String, bool)> {
        vec![("ssh".into(), "SSH".into(), true)]
    }

    fn list_ports(&self) -> Vec<(String, String)> {
        vec![("443".into(), "tcp".into())]
    }

    fn add_port(&self, _port: &str, _protocol: &str) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct UnusedAuthenticator;
impl auth::Authenticator for UnusedAuthenticator {
    fn authenticate(&self, _: &str, _: &str) -> Result<(), String> {
        panic!("tests seed sessions; host PAM must not run")
    }
}

fn cookie_header(key: &Key, token: &str) -> String {
    let response = PrivateCookieJar::new(key.clone())
        .add(Cookie::new(state::SESSION_COOKIE, token.to_string()))
        .into_response();
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    cookie: &str,
    body: &str,
) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ).as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }).await.expect("HTTP request timed out")
}

#[tokio::test]
#[ignore = "requires a private D-Bus: bash scripts/check-authorization-contracts.sh"]
async fn authorization_integration_rejects_writes_without_calling_daemon() {
    assert_eq!(
        std::env::var("VEGA_WEB_TEST_PRIVATE_BUS").as_deref(),
        Ok("1"),
        "run through scripts/check-authorization-contracts.sh"
    );
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").expect("private bus address");
    assert!(!address.is_empty());
    assert_eq!(std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap(), address);
    // This fake daemon accepts both writes, even from the shared service
    // connection. It detects regressions independently of Polkit policy.
    let writes = Arc::new(AtomicUsize::new(0));
    let _daemon = zbus::connection::Builder::system()
        .unwrap()
        .name(lyra_vega_dbus::BUS_NAME)
        .unwrap()
        .serve_at(lyra_vega_dbus::OBJECT_PATH, Software(writes.clone()))
        .unwrap()
        .serve_at(lyra_vega_dbus::OBJECT_PATH, Firewall(writes.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let dbus = lyra_vega_dbus::VegaDbus::connect().await.unwrap();
    // Positive controls: prove the fake methods and counters work.
    dbus.software().install("official", "test").await.unwrap();
    dbus.firewall().add_port("443", "tcp").await.unwrap();
    assert_eq!(writes.swap(0, Ordering::SeqCst), 2);

    let key = Key::generate();
    let sessions = SessionStore::new(SessionPolicy::default());
    let state = AppState {
        dbus,
        sessions: sessions.clone(),
        cookie_key: key.clone(),
        authenticator: Arc::new(UnusedAuthenticator),
        login_limiter: LoginLimiter::new(LoginPolicy::default()),
        pam_slots: Arc::new(Semaphore::new(1)),
        terminal_grants: TerminalGrants::default(),
        terminal_slots: Arc::new(Semaphore::new(1)),
        terminal_socket: "/unused-test-terminal.sock".into(),
    };
    let router = build_router(state);
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(tcp, router).await.unwrap() });

    for username in ["root", "nobody"] {
        sessions.insert(
            username.into(),
            state::Session::new(username.into(), Instant::now()),
        );
        let cookie = cookie_header(&key, username);
        for (path, body, content) in [
            (
                "/software?q=test&install=started&tx=123",
                "package=test&username=root&uid=0",
                "Test package",
            ),
            (
                "/rede?firewall=added",
                "port=443&protocol=tcp&username=root&uid=0",
                "SSH",
            ),
        ] {
            let response = request(address, "GET", path, &cookie, "").await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.contains(content), "{response}");
            assert!(response.contains(pages::ADMINISTRATION_UNAVAILABLE_NOTICE));
            assert!(!response.contains(">Instalar</button>"));
            assert!(!response.contains("Adicionar regra"));
            assert!(!response.contains("Instalação iniciada"));
            assert!(!response.contains("Regra adicionada"));
            let route = path.split('?').next().unwrap();
            assert!(!response.contains(&format!("method=\"post\" action=\"{route}\"")));

            // Old browser forms, forged identity, empty and malformed input all
            // remain unavailable. No body interpretation can enable the action.
            for payload in [body, "", "%invalid=\"<script>"] {
                let response = request(address, "POST", path, &cookie, payload).await;
                assert!(response.starts_with("HTTP/1.1 403"), "{response}");
                assert!(response.contains(pages::ADMINISTRATION_UNAVAILABLE_NOTICE));
                assert_eq!(writes.load(Ordering::SeqCst), 0);
            }
            for method in ["PUT", "PATCH", "DELETE"] {
                let response = request(address, method, path, &cookie, body).await;
                assert!(response.starts_with("HTTP/1.1 405"), "{response}");
            }
        }
        sessions.remove(username);
        for cookie in [cookie.as_str(), ""] {
            for path in ["/software", "/rede"] {
                for method in ["GET", "POST"] {
                    let response = request(address, method, path, cookie, "").await;
                    assert!(response.starts_with("HTTP/1.1 303"), "{response}");
                    assert!(response.contains("location: /login\r\n"));
                }
            }
        }
        eprintln!("PASS: read-only pages and rejected writes for session identity {username}");
    }
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    eprintln!("PASS: no HTTP request invoked Software.Install or Firewall.AddPort");
    server.abort();
}
