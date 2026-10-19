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
<table><thead><tr><th>Nome</th><th>Estado</th><th>IPv4</th><th>MAC</th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Err(error) => body.push_str(&error_body("Lista de interfaces indisponível", error)),
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
                        if network.active { "conectada" } else { "" },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<h3>Wi-Fi</h3>
<table><thead><tr><th>SSID</th><th>Segurança</th><th>Sinal</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body("Lista de redes Wi-Fi indisponível", error)),
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
        Err(error) => body.push_str(&error_body("Configuração de proxy indisponível", error)),
    }

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
                "Estado",
                &format!(
                    r#"<span class="badge {}">{}</span>"#,
                    if status.enabled { "on" } else { "off" },
                    if status.enabled { "ativo" } else { "inativo" },
                )
            ),
            icon_stat("network", "Zona ativa", &html_escape(&status.active_zone)),
        )),
        Err(error) => body.push_str(&error_body("Status do firewall indisponível", error)),
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
                            "Bloquear",
                            "firewall-service",
                            &[("name", &service.name), ("enabled", "false")],
                        )
                    } else {
                        actions.button(
                            "Permitir",
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
                            "permitido"
                        } else {
                            "bloqueado"
                        },
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<table><thead><tr><th>Serviço</th><th>Estado</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
            let rows: String = ports
                .iter()
                .map(|rule| {
                    let close = actions.button(
                        "Fechar",
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
                r#"<p class="empty">Nenhuma regra de porta personalizada.</p>"#.to_owned()
            } else {
                format!(
                    r#"<table><thead><tr><th>Porta</th><th>Protocolo</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#
                )
            };
            body.push_str(&format!("<h3>Regras de porta personalizadas</h3>{table}"));
        }
        Err(error) if actions.enabled() => {
            body.push_str(&actions.unlock(ReadQuery::Firewall, "Serviços e portas do firewall"));
            body.push_str(&error_body("Leitura direta recusada", error));
        }
        Err(error) => body.push_str(&error_body(
            "Serviços e portas do firewall indisponíveis",
            error,
        )),
    }
    if actions.enabled() {
        body.push_str(&actions.inline_form(
            "Abrir porta",
            "add-port",
            r#"<label>Porta<input type="number" name="port" min="1" max="65535" required></label><label>Protocolo<select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>"#,
        ));
    }

    render_with("Rede e Firewall", "/rede", &user, "", "", body)
}
