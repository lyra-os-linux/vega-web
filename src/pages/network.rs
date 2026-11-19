use axum::extract::{Extension, State};
use axum::response::Html;
use axum_extra::extract::PrivateCookieJar;
use lyra_vega_dbus::{FirewallClient, NetworkClient};
use vega_web::admin_read::{Firewall, FirewallPort, FirewallService, ReadQuery};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::{bar, icon_stat};
use super::{Actions, cached_read, error_body, html_escape, render_with};

pub async fn handler(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let lang = user.lang;
    let t = move |pt: &'static str, en: &'static str, es: &'static str| lang.text(pt, en, es);
    let actions = Actions::new(&state, &jar, &user);
    let mut body = actions.notice();
    let net = state.dbus.network();

    match net.interfaces().await {
        Ok(interfaces) => {
            let rows: String = interfaces
                .iter()
                .map(|iface| {
                    format!(
                        "<tr><td>{}<br><small>{}</small></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&iface.name),
                        html_escape(&iface.kind),
                        html_escape(&iface.state),
                        html_escape(&iface.ipv4),
                        html_escape(&iface.mac),
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<h3>Interfaces</h3>
<table><thead><tr><th>{}</th><th>{}</th><th>IPv4</th><th>MAC</th></tr></thead><tbody>{rows}</tbody></table>"#,
                t("Nome", "Name", "Nombre"),
                t("Estado", "State", "Estado"),
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Lista de interfaces indisponível",
                "Interface list unavailable",
                "Lista de interfaces no disponible",
            ),
            error,
        )),
    }

    match net.wifi().await {
        Ok(networks) if !networks.is_empty() => {
            let rows: String = networks
                .iter()
                .map(|network| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}%{}</td><td><span class=\"badge {}\">{}</span></td></tr>",
                        html_escape(&network.ssid),
                        html_escape(&network.security),
                        network.signal,
                        bar(network.signal as f64),
                        if network.active { "on" } else { "off" },
                        if network.active {
                            t("conectada", "connected", "conectada")
                        } else {
                            ""
                        },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<h3>Wi-Fi</h3>
<table><thead><tr><th>SSID</th><th>{}</th><th>{}</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#,
                t("Segurança", "Security", "Seguridad"),
                t("Sinal", "Signal", "Señal"),
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Lista de redes Wi-Fi indisponível",
                "Wi-Fi network list unavailable",
                "Lista de redes Wi-Fi no disponible",
            ),
            error,
        )),
    }

    match net.proxy().await {
        Ok(proxy)
            if !proxy.http.is_empty() || !proxy.https.is_empty() || !proxy.socks.is_empty() =>
        {
            body.push_str(&format!(
                r#"<h3>Proxy</h3>
<div class="cards">
{}
{}
{}
</div>"#,
                icon_stat("network", "HTTP", &html_escape(&proxy.http)),
                icon_stat("network", "HTTPS", &html_escape(&proxy.https)),
                icon_stat("network", "SOCKS", &html_escape(&proxy.socks)),
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Configuração de proxy indisponível",
                "Proxy configuration unavailable",
                "Configuración de proxy no disponible",
            ),
            error,
        )),
    }

    body.push_str(&format!(
        r#"<div class="notice"><strong>{}</strong><span>{}</span><a class="button-link" href="/rede/internet">{}</a></div>"#,
        t(
            "Minha internet não funciona",
            "My internet does not work",
            "Mi internet no funciona",
        ),
        t(
            "Testa a conexão passo a passo, do cabo até a internet, e aponta onde está o problema.",
            "Tests the connection step by step, from the cable to the internet, and points out where the problem is.",
            "Prueba la conexión paso a paso, del cable a internet, e indica dónde está el problema.",
        ),
        t("Testar a conexão", "Test the connection", "Probar la conexión"),
    ));

    let firewall = state.dbus.firewall();
    match firewall.status().await {
        Ok(status) => body.push_str(&format!(
            r#"<h3>Firewall</h3>
<div class="cards">
{}
{}
</div>"#,
            icon_stat(
                "firewall",
                t("Estado", "State", "Estado"),
                &format!(
                    r#"<span class="badge {}">{}</span>"#,
                    if status.enabled { "on" } else { "off" },
                    if status.enabled {
                        t("ativo", "active", "activo")
                    } else {
                        t("inativo", "inactive", "inactivo")
                    },
                )
            ),
            icon_stat(
                "network",
                t("Zona ativa", "Active zone", "Zona activa"),
                &html_escape(&status.active_zone)
            ),
        )),
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Status do firewall indisponível",
                "Firewall status unavailable",
                "Estado del firewall no disponible",
            ),
            error,
        )),
    }

    let lists = match cached_read::<Firewall>(&state, &jar, ReadQuery::Firewall) {
        Some(payload) => Ok(payload),
        None => match (firewall.services().await, firewall.ports().await) {
            (Ok(services), Ok(ports)) => Ok(Firewall {
                services: services
                    .into_iter()
                    .map(|service| FirewallService {
                        name: service.name,
                        label: service.label,
                        enabled: service.enabled,
                    })
                    .collect(),
                ports: ports
                    .into_iter()
                    .map(|port| FirewallPort {
                        port: port.port,
                        protocol: port.protocol,
                    })
                    .collect(),
            }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        },
    };
    match lists {
        Ok(Firewall { services, ports }) => {
            let rows: String = services
                .iter()
                .map(|service| {
                    let toggle = if service.enabled {
                        actions.button(
                            t("Bloquear", "Block", "Bloquear"),
                            "firewall-service",
                            &[("name", &service.name), ("enabled", "false")],
                        )
                    } else {
                        actions.button(
                            t("Permitir", "Allow", "Permitir"),
                            "firewall-service",
                            &[("name", &service.name), ("enabled", "true")],
                        )
                    };
                    format!(
                        "<tr><td>{}<small>{}</small></td><td><span class=\"badge {}\">{}</span></td><td><div class=\"row-actions\">{toggle}</div></td></tr>",
                        html_escape(&service.label),
                        html_escape(&service.name),
                        if service.enabled { "on" } else { "off" },
                        if service.enabled {
                            t("permitido", "allowed", "permitido")
                        } else {
                            t("bloqueado", "blocked", "bloqueado")
                        },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<table><thead><tr><th>{}</th><th>{}</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#,
                t("Serviço", "Service", "Servicio"),
                t("Estado", "State", "Estado"),
            ));
            let rows: String = ports
                .iter()
                .map(|rule| {
                    let close = actions.button(
                        t("Fechar", "Close", "Cerrar"),
                        "remove-port",
                        &[("port", &rule.port), ("protocol", &rule.protocol)],
                    );
                    format!(
                        "<tr><td>{}</td><td>{}</td><td><div class=\"row-actions\">{close}</div></td></tr>",
                        html_escape(&rule.port),
                        html_escape(&rule.protocol),
                    )
                })
                .collect();
            let table = if rows.is_empty() {
                format!(
                    r#"<p class="empty">{}</p>"#,
                    t(
                        "Nenhuma regra de porta personalizada.",
                        "No custom port rule.",
                        "Ninguna regla de puerto personalizada.",
                    )
                )
            } else {
                format!(
                    r#"<table><thead><tr><th>{}</th><th>{}</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#,
                    t("Porta", "Port", "Puerto"),
                    t("Protocolo", "Protocol", "Protocolo"),
                )
            };
            body.push_str(&format!(
                "<h3>{}</h3>{table}",
                t(
                    "Regras de porta personalizadas",
                    "Custom port rules",
                    "Reglas de puerto personalizadas",
                )
            ));
        }
        Err(error) if actions.enabled() => {
            body.push_str(&actions.unlock(
                ReadQuery::Firewall,
                t(
                    "Serviços e portas do firewall",
                    "Firewall services and ports",
                    "Servicios y puertos del firewall",
                ),
            ));
            body.push_str(&error_body(
                lang,
                t(
                    "Leitura direta recusada",
                    "Direct read refused",
                    "Lectura directa rechazada",
                ),
                error,
            ));
        }
        Err(error) => body.push_str(&error_body(
            lang,
            t(
                "Serviços e portas do firewall indisponíveis",
                "Firewall services and ports unavailable",
                "Servicios y puertos del firewall no disponibles",
            ),
            error,
        )),
    }
    if actions.enabled() {
        body.push_str(&actions.inline_form(
            t("Abrir porta", "Open port", "Abrir puerto"),
            "add-port",
            &format!(
                r#"<label>{}<input type="number" name="port" min="1" max="65535" required></label><label>{}<select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>"#,
                t("Porta", "Port", "Puerto"),
                t("Protocolo", "Protocol", "Protocolo"),
            ),
        ));
    }

    render_with(
        t("Rede e Firewall", "Network and Firewall", "Red y Firewall"),
        "/rede",
        &user,
        "",
        "",
        body,
    )
}
