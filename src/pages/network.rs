use axum::extract::{Extension, State};
use axum::response::Html;
use lyra_vega_dbus::{FirewallClient, NetworkClient};

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::{error_body, html_escape, render};

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Html<String> {
    let mut body = String::new();
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
                        "<tr><td>{}</td><td>{}</td><td>{}%</td><td><span class=\"badge {}\">{}</span></td></tr>",
                        html_escape(&network.ssid),
                        html_escape(&network.security),
                        network.signal,
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
<div class="card">HTTP<strong>{}</strong></div>
<div class="card">HTTPS<strong>{}</strong></div>
<div class="card">SOCKS<strong>{}</strong></div>
</div>"#,
                html_escape(&proxy.http),
                html_escape(&proxy.https),
                html_escape(&proxy.socks),
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
<div class="card">Estado<strong><span class="badge {}">{}</span></strong></div>
<div class="card">Zona ativa<strong>{}</strong></div>
</div>"#,
            if status.enabled { "on" } else { "off" },
            if status.enabled { "ativo" } else { "inativo" },
            html_escape(&status.active_zone),
        )),
        Err(error) => body.push_str(&error_body("Status do firewall indisponível", error)),
    }

    match firewall.services().await {
        Ok(services) => {
            let rows: String = services
                .iter()
                .map(|service| {
                    format!(
                        "<tr><td>{}</td><td><span class=\"badge {}\">{}</span></td></tr>",
                        html_escape(&service.label),
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
                r#"<table><thead><tr><th>Serviço</th><th>Estado</th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Err(error) => body.push_str(&error_body(
            "Lista de serviços do firewall indisponível",
            error,
        )),
    }

    match firewall.ports().await {
        Ok(ports) if !ports.is_empty() => {
            let rows: String = ports
                .iter()
                .map(|rule| {
                    format!(
                        "<tr><td>{}</td><td>{}</td></tr>",
                        html_escape(&rule.port),
                        html_escape(&rule.protocol),
                    )
                })
                .collect();
            body.push_str(&format!(
                r#"<h3>Regras de porta personalizadas</h3>
<p>Somente leitura nesta versão — criar/remover regras está disponível no vega-gtk.</p>
<table><thead><tr><th>Porta</th><th>Protocolo</th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Ok(_) => {}
        Err(error) => body.push_str(&error_body("Lista de regras de porta indisponível", error)),
    }

    render("Rede e Firewall", "/rede", &user.0, body)
}
