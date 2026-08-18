use axum::Form;
use axum::extract::{Extension, Query, State};
use axum::response::{Html, Redirect};
use lyra_vega_dbus::{FirewallClient, NetworkClient};
use serde::Deserialize;

use crate::auth::CurrentUser;
use crate::state::AppState;

use super::widgets::{bar, icon_stat};
use super::{error_body, html_escape, render};

#[derive(Default, Deserialize)]
pub struct NetworkQuery {
    #[serde(default)]
    firewall: String,
}

#[derive(Deserialize)]
pub struct FirewallRuleForm {
    port: String,
    protocol: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<NetworkQuery>,
) -> Html<String> {
    let mut body = String::new();
    match query.firewall.as_str() {
        "added" => body.push_str(r#"<p class="notice success">Regra adicionada e firewall recarregado.</p>"#),
        "invalid" => body.push_str(r#"<p class="error" role="alert">Informe uma porta entre 1 e 65535 ou um intervalo válido.</p>"#),
        "error" => body.push_str(r#"<p class="error" role="alert">Não foi possível adicionar a regra. Verifique a autorização e tente novamente.</p>"#),
        _ => {}
    }
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
        Ok(ports) => {
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
<form class="inline-form" method="post" action="/rede">
<label for="firewall-port">Porta ou intervalo<input id="firewall-port" name="port" inputmode="numeric" placeholder="Ex.: 8080 ou 9000-9010" required></label>
<label for="firewall-protocol">Protocolo<select id="firewall-protocol" name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
<button type="submit">Adicionar regra</button>
</form>
<table><thead><tr><th>Porta</th><th>Protocolo</th></tr></thead><tbody>{rows}</tbody></table>"#
            ));
        }
        Err(error) => body.push_str(&error_body("Lista de regras de porta indisponível", error)),
    }

    render("Rede e Firewall", "/rede", &user.0, body)
}

pub async fn add_firewall_rule(
    State(state): State<AppState>,
    Extension(_user): Extension<CurrentUser>,
    Form(form): Form<FirewallRuleForm>,
) -> Redirect {
    let port = form.port.trim();
    let protocol = form.protocol.trim().to_ascii_lowercase();
    if !valid_port_or_range(port) || !matches!(protocol.as_str(), "tcp" | "udp") {
        return Redirect::to("/rede?firewall=invalid");
    }

    match state.dbus.firewall().add_port(port, &protocol).await {
        Ok(()) => Redirect::to("/rede?firewall=added"),
        Err(error) => {
            eprintln!("vega-web: falha ao adicionar regra de firewall: {error}");
            Redirect::to("/rede?firewall=error")
        }
    }
}

fn valid_port_or_range(value: &str) -> bool {
    let valid = |part: &str| part.parse::<u16>().is_ok_and(|port| port > 0);
    match value.split_once('-') {
        Some((start, end)) => {
            valid(start)
                && valid(end)
                && start.parse::<u16>().expect("porta inicial já validada")
                    <= end.parse::<u16>().expect("porta final já validada")
        }
        None => valid(value),
    }
}

#[cfg(test)]
mod tests {
    use super::valid_port_or_range;

    #[test]
    fn firewall_port_validation_accepts_ports_and_ordered_ranges() {
        assert!(valid_port_or_range("443"));
        assert!(valid_port_or_range("8000-8010"));
        assert!(!valid_port_or_range("0"));
        assert!(!valid_port_or_range("9000-8000"));
        assert!(!valid_port_or_range("22/tcp"));
    }
}
