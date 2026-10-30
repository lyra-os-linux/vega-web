//! A PAM-authenticated, single-use operation over a peer-checked Unix socket.
//! The grant never reaches the browser. Dropping the client connection revokes
//! an unconsumed grant; a committed daemon transaction must finish normally.
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::admin_read::{MAX_PAYLOAD, ReadQuery};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const GRANT_TIMEOUT: Duration = Duration::from_secs(10);
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(70);
const MAGIC: &[u8; 4] = b"VWA1";
const COMMIT: &[u8; 4] = b"VWC1";
// Longest operation frame: a code byte, the job and the findings list
// (16 pairs of a test id and an index).
const MAX_OPERATION: usize = 512;
/// Findings fixed by one `RepairFindings`.
const MAX_FINDINGS: usize = 16;
const MAX_NAME: usize = 200;

/// One administrative operation, authorized by the user's own password through
/// the root broker and executed by vegad with the user's identity. Each variant
/// maps to exactly one polkit action; the wire encoding is a code byte followed
/// by fixed fields, with no free-form parsing on the privileged side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    InstallNative(String),
    InstallNvidia,
    AddPort {
        port: u16,
        tcp: bool,
    },
    RemovePort {
        port: u16,
        tcp: bool,
    },
    FirewallService {
        name: String,
        enabled: bool,
    },
    ServiceEnabled {
        name: String,
        enabled: bool,
    },
    ServiceRunning {
        name: String,
        running: bool,
    },
    ServiceRestart(String),
    UpdateAllNative,
    RemoveNative(String),
    RepoEnabled {
        name: String,
        enabled: bool,
    },
    ClearNativeCache,
    SetAdmin {
        username: String,
        admin: bool,
    },
    DateTime {
        timezone: String,
        ntp: bool,
    },
    /// An administrative read, answered with a JSON payload.
    Read(ReadQuery),
    /// Health check tests by id (`Diagnostics.Start`); the network test
    /// alone is `NetworkCheck`.
    DiagnosticsStart(Vec<String>),
    /// The network test, its wait and its report in one operation.
    NetworkCheck,
    DiagnosticsReport {
        job: u32,
        redact: bool,
    },
    RepairFindings {
        job: u32,
        findings: Vec<(String, u32)>,
    },
    MarkLogsSeen(u32),
    SetPeriodic {
        enabled: bool,
        daily: bool,
    },
    /// System cleanup categories by id (`Cleanup.Clean`).
    CleanupClean(Vec<String>),
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid administrative frame")
}

fn checked_name(name: &str, extra: &[u8]) -> io::Result<String> {
    if name.is_empty()
        || name.len() > MAX_NAME
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
    {
        return Err(invalid());
    }
    Ok(name.to_owned())
}

fn flag(value: &str) -> io::Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid()),
    }
}

fn port_number(port: &str, protocol: &str) -> io::Result<(u16, bool)> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if port == 0 || !matches!(protocol, "tcp" | "udp") {
        return Err(invalid());
    }
    Ok((port, protocol == "tcp"))
}

/// A comma-separated list of distinct ids, each one from `known`.
fn known_list(list: &str, known: &[&str], max: usize) -> io::Result<Vec<String>> {
    let ids: Vec<String> = list.split(',').map(str::to_owned).collect();
    if ids.is_empty() || ids.len() > max {
        return Err(invalid());
    }
    for (index, id) in ids.iter().enumerate() {
        if !known.contains(&id.as_str()) || ids[..index].contains(id) {
            return Err(invalid());
        }
    }
    Ok(ids)
}

fn job_number(job: &str) -> io::Result<u32> {
    if job.is_empty() || job.len() > 10 || !job.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    match job.parse() {
        Ok(job) if job > 0 => Ok(job),
        _ => Err(invalid()),
    }
}

fn job_bytes(code: u8, flag: Option<bool>, job: u32) -> Vec<u8> {
    let mut bytes = vec![code];
    if let Some(flag) = flag {
        bytes.push(u8::from(flag));
    }
    bytes.extend_from_slice(&job.to_be_bytes());
    bytes
}

impl Operation {
    /// Test ids such as `packages,logs,network`; never the network test alone.
    pub fn diagnostics_start(tests: &str) -> io::Result<Self> {
        let tests = known_list(tests, lyra_vega_dbus::DIAGNOSTIC_TEST_IDS, 16)?;
        if tests == ["network"] {
            return Err(invalid());
        }
        Ok(Self::DiagnosticsStart(tests))
    }

    /// Job 0 is the most recent report, as in `Diagnostics.Report`.
    pub fn diagnostics_report(job: &str, redact: &str) -> io::Result<Self> {
        Ok(Self::DiagnosticsReport {
            job: if job == "0" { 0 } else { job_number(job)? },
            redact: flag(redact)?,
        })
    }

    /// Findings such as `logs:0,security:2`, the pairs `Remedies` returns.
    pub fn repair_findings(job: &str, findings: &str) -> io::Result<Self> {
        let job = job_number(job)?;
        let mut pairs = Vec::new();
        for item in findings.split(',') {
            let (stage, index) = item.split_once(':').ok_or_else(invalid)?;
            if !lyra_vega_dbus::DIAGNOSTIC_TEST_IDS.contains(&stage)
                || index.is_empty()
                || index.len() > 3
                || !index.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid());
            }
            let pair = (stage.to_owned(), index.parse().map_err(|_| invalid())?);
            if pairs.contains(&pair) {
                return Err(invalid());
            }
            pairs.push(pair);
        }
        if pairs.is_empty() || pairs.len() > MAX_FINDINGS {
            return Err(invalid());
        }
        Ok(Self::RepairFindings {
            job,
            findings: pairs,
        })
    }

    pub fn mark_logs_seen(job: &str) -> io::Result<Self> {
        Ok(Self::MarkLogsSeen(job_number(job)?))
    }

    /// `weekly` or `daily`, the frequencies vegad accepts.
    pub fn set_periodic(enabled: &str, frequency: &str) -> io::Result<Self> {
        let daily = match frequency {
            "weekly" => false,
            "daily" => true,
            _ => return Err(invalid()),
        };
        Ok(Self::SetPeriodic {
            enabled: flag(enabled)?,
            daily,
        })
    }

    /// Category ids such as `journal,package-cache`.
    pub fn cleanup_clean(categories: &str) -> io::Result<Self> {
        Ok(Self::CleanupClean(known_list(
            categories,
            lyra_vega_dbus::CLEANUP_CATEGORY_IDS,
            lyra_vega_dbus::CLEANUP_CATEGORY_IDS.len(),
        )?))
    }

    fn findings_text(findings: &[(String, u32)]) -> String {
        findings
            .iter()
            .map(|(stage, index)| format!("{stage}:{index}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Native package names: RPM names such as `libstdc++6` or `python3.12`.
    pub fn install(name: &str) -> io::Result<Self> {
        Ok(Self::InstallNative(checked_name(name, b"+_.-")?))
    }

    pub fn remove(name: &str) -> io::Result<Self> {
        Ok(Self::RemoveNative(checked_name(name, b"+_.-")?))
    }

    pub fn port(port: &str, protocol: &str) -> io::Result<Self> {
        let (port, tcp) = port_number(port, protocol)?;
        Ok(Self::AddPort { port, tcp })
    }

    pub fn remove_port(port: &str, protocol: &str) -> io::Result<Self> {
        let (port, tcp) = port_number(port, protocol)?;
        Ok(Self::RemovePort { port, tcp })
    }

    /// firewalld service ids such as `ssh` or `dhcpv6-client`.
    pub fn firewall_service(name: &str, enabled: &str) -> io::Result<Self> {
        Ok(Self::FirewallService {
            name: checked_name(name, b"_-")?,
            enabled: flag(enabled)?,
        })
    }

    /// systemd unit names such as `sshd.service` or `getty@tty1.service`.
    fn unit(name: &str) -> io::Result<String> {
        let name = checked_name(name, b"@_.:\\-")?;
        if !name.ends_with(".service") {
            return Err(invalid());
        }
        Ok(name)
    }

    pub fn service_enabled(name: &str, enabled: &str) -> io::Result<Self> {
        Ok(Self::ServiceEnabled {
            name: Self::unit(name)?,
            enabled: flag(enabled)?,
        })
    }

    pub fn service_running(name: &str, running: &str) -> io::Result<Self> {
        Ok(Self::ServiceRunning {
            name: Self::unit(name)?,
            running: flag(running)?,
        })
    }

    pub fn service_restart(name: &str) -> io::Result<Self> {
        Ok(Self::ServiceRestart(Self::unit(name)?))
    }

    /// Zypper repository aliases such as `repo-oss` or `home:user:project`.
    pub fn repo_enabled(name: &str, enabled: &str) -> io::Result<Self> {
        Ok(Self::RepoEnabled {
            name: checked_name(name, b"+_.:-")?,
            enabled: flag(enabled)?,
        })
    }

    /// POSIX account names; root and the service account are refused by the
    /// broker and by vegad, this only bounds the frame.
    pub fn set_admin(username: &str, admin: &str) -> io::Result<Self> {
        if username.len() > 32 || !username.as_bytes()[0].is_ascii_lowercase() {
            return Err(invalid());
        }
        Ok(Self::SetAdmin {
            username: checked_name(username, b"_.-")?,
            admin: flag(admin)?,
        })
    }

    /// IANA zone names such as `America/Sao_Paulo`, `UTC` or `Etc/GMT+3`.
    pub fn datetime(timezone: &str, ntp: &str) -> io::Result<Self> {
        let timezone = checked_name(timezone, b"/_+-")?;
        if timezone.len() > 100 || timezone.contains("//") || timezone.ends_with('/') {
            return Err(invalid());
        }
        Ok(Self::DateTime {
            timezone,
            ntp: flag(ntp)?,
        })
    }

    pub fn action_id(&self) -> &'static str {
        match self {
            Self::InstallNative(_) | Self::InstallNvidia => "org.lyraos.vega.software.install",
            Self::UpdateAllNative => "org.lyraos.vega.software.update",
            Self::RemoveNative(_) => "org.lyraos.vega.software.remove",
            Self::RepoEnabled { .. } => "org.lyraos.vega.software.manage-repos",
            Self::ClearNativeCache => "org.lyraos.vega.software.clear-cache",
            Self::AddPort { .. } | Self::RemovePort { .. } | Self::FirewallService { .. } => {
                "org.lyraos.vega.firewall.configure"
            }
            Self::ServiceEnabled { .. } | Self::ServiceRunning { .. } | Self::ServiceRestart(_) => {
                "org.lyraos.vega.services.configure"
            }
            Self::SetAdmin { .. } => "org.lyraos.vega.users.manage",
            Self::DateTime { .. } => "org.lyraos.vega.system.configure",
            Self::Read(query) => query.action_id(),
            Self::DiagnosticsStart(_) | Self::MarkLogsSeen(_) | Self::SetPeriodic { .. } => {
                "org.lyraos.vega.hardware.diagnose"
            }
            Self::NetworkCheck => "org.lyraos.vega.network.diagnose",
            // vegad uses network.diagnose for a report of the network test
            // alone, which then needs no challenge.
            Self::DiagnosticsReport { .. } => "org.lyraos.vega.logs.read-admin",
            Self::RepairFindings { .. } => "org.lyraos.vega.hardware.repair",
            Self::CleanupClean(_) => "org.lyraos.vega.storage.cleanup",
        }
    }

    /// Page the operation belongs to; the confirmation and result pages link back to it.
    pub fn return_href(&self) -> &'static str {
        match self {
            Self::InstallNative(_)
            | Self::UpdateAllNative
            | Self::RemoveNative(_)
            | Self::RepoEnabled { .. }
            | Self::ClearNativeCache => "/software",
            Self::InstallNvidia => "/hardware/nvidia",
            Self::AddPort { .. } | Self::RemovePort { .. } | Self::FirewallService { .. } => {
                "/rede"
            }
            Self::ServiceEnabled { .. } | Self::ServiceRunning { .. } | Self::ServiceRestart(_) => {
                "/servicos"
            }
            Self::SetAdmin { .. } => "/usuarios",
            Self::DateTime { .. } => "/data-hora",
            Self::Read(query) => query.return_href(),
            Self::DiagnosticsStart(_)
            | Self::DiagnosticsReport { .. }
            | Self::RepairFindings { .. }
            | Self::MarkLogsSeen(_)
            | Self::SetPeriodic { .. } => "/hardware/diagnostico",
            Self::NetworkCheck => "/rede/internet",
            Self::CleanupClean(_) => "/armazenamento",
        }
    }

    /// Human description (pt-BR) for the confirmation dialog and the result page.
    pub fn describe(&self) -> String {
        let proto = |tcp: &bool| if *tcp { "tcp" } else { "udp" };
        match self {
            Self::InstallNative(name) => format!("Instalar o pacote {name}"),
            Self::InstallNvidia => "Instalar o driver NVIDIA oficial".to_owned(),
            Self::AddPort { port, tcp } => {
                format!("Abrir a porta {port}/{} no firewall", proto(tcp))
            }
            Self::RemovePort { port, tcp } => {
                format!("Fechar a porta {port}/{} no firewall", proto(tcp))
            }
            Self::FirewallService {
                name,
                enabled: true,
            } => {
                format!("Permitir o serviço {name} no firewall")
            }
            Self::FirewallService {
                name,
                enabled: false,
            } => {
                format!("Bloquear o serviço {name} no firewall")
            }
            Self::ServiceEnabled {
                name,
                enabled: true,
            } => {
                format!("Habilitar {name} na inicialização")
            }
            Self::ServiceEnabled {
                name,
                enabled: false,
            } => {
                format!("Desabilitar {name} na inicialização")
            }
            Self::ServiceRunning {
                name,
                running: true,
            } => format!("Iniciar {name}"),
            Self::ServiceRunning {
                name,
                running: false,
            } => format!("Parar {name}"),
            Self::ServiceRestart(name) => format!("Reiniciar {name}"),
            Self::UpdateAllNative => "Aplicar todas as atualizações disponíveis".to_owned(),
            Self::RemoveNative(name) => format!("Remover o pacote {name}"),
            Self::RepoEnabled {
                name,
                enabled: true,
            } => format!("Habilitar o repositório {name}"),
            Self::RepoEnabled {
                name,
                enabled: false,
            } => {
                format!("Desabilitar o repositório {name}")
            }
            Self::ClearNativeCache => "Limpar o cache de pacotes".to_owned(),
            Self::SetAdmin {
                username,
                admin: true,
            } => {
                format!("Tornar {username} administrador")
            }
            Self::SetAdmin {
                username,
                admin: false,
            } => {
                format!("Retirar {username} dos administradores")
            }
            Self::DateTime { timezone, ntp } => format!(
                "Definir o fuso horário {timezone} e {} a sincronização automática (NTP)",
                if *ntp { "ativar" } else { "desativar" }
            ),
            Self::Read(query) => query.describe().to_owned(),
            Self::DiagnosticsStart(tests) => format!(
                "Executar o diagnóstico de saúde: {}",
                tests
                    .iter()
                    .map(|id| crate::diagnostics_text::test_name(id))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::NetworkCheck => "Testar a conexão com a internet".to_owned(),
            Self::DiagnosticsReport {
                job: 0,
                redact: false,
            } => "Ler o último relatório do diagnóstico (inclui trechos do journal)".to_owned(),
            Self::DiagnosticsReport { job, redact: false } => {
                format!("Ler o relatório do diagnóstico {job} (inclui trechos do journal)")
            }
            Self::DiagnosticsReport { job, redact: true } => {
                format!("Ler o relatório redigido do diagnóstico {job} para pedir ajuda")
            }
            Self::RepairFindings { findings, .. } => format!(
                "Corrigir {} achado(s) do diagnóstico (um snapshot é criado antes)",
                findings.len()
            ),
            Self::MarkLogsSeen(job) => {
                format!("Marcar como vistos os logs registrados até o diagnóstico {job}")
            }
            Self::SetPeriodic { enabled: false, .. } => {
                "Desligar a verificação periódica".to_owned()
            }
            Self::SetPeriodic {
                enabled: true,
                daily,
            } => format!(
                "Ligar a verificação periódica, {}",
                if *daily { "todo dia" } else { "toda semana" }
            ),
            Self::CleanupClean(ids) => format!(
                "Liberar espaço: {}",
                ids.iter()
                    .map(|id| crate::diagnostics_text::cleanup_name(id))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let named = |code: u8, flag: Option<bool>, name: &str| {
            let mut bytes = vec![code];
            if let Some(flag) = flag {
                bytes.push(u8::from(flag));
            }
            bytes.extend_from_slice(name.as_bytes());
            Ok(bytes)
        };
        match self {
            Self::InstallNvidia => Ok(vec![3]),
            Self::InstallNative(name) => {
                Self::install(name)?;
                named(1, None, name)
            }
            Self::AddPort { port, tcp } | Self::RemovePort { port, tcp } if *port > 0 => {
                let mut bytes = vec![if matches!(self, Self::AddPort { .. }) {
                    2
                } else {
                    4
                }];
                bytes.extend_from_slice(&port.to_be_bytes());
                bytes.push(u8::from(*tcp));
                Ok(bytes)
            }
            Self::FirewallService { name, enabled } => {
                Self::firewall_service(name, "true")?;
                named(5, Some(*enabled), name)
            }
            Self::ServiceEnabled { name, enabled } => {
                Self::unit(name)?;
                named(6, Some(*enabled), name)
            }
            Self::ServiceRunning { name, running } => {
                Self::unit(name)?;
                named(7, Some(*running), name)
            }
            Self::ServiceRestart(name) => {
                Self::unit(name)?;
                named(8, None, name)
            }
            Self::UpdateAllNative => Ok(vec![9]),
            Self::RemoveNative(name) => {
                Self::remove(name)?;
                named(10, None, name)
            }
            Self::RepoEnabled { name, enabled } => {
                Self::repo_enabled(name, "true")?;
                named(11, Some(*enabled), name)
            }
            Self::ClearNativeCache => Ok(vec![12]),
            Self::Read(query) => Ok(vec![query.code()]),
            Self::SetAdmin { username, admin } => {
                Self::set_admin(username, "true")?;
                named(13, Some(*admin), username)
            }
            Self::DateTime { timezone, ntp } => {
                Self::datetime(timezone, "true")?;
                named(14, Some(*ntp), timezone)
            }
            Self::DiagnosticsStart(tests) => {
                let list = tests.join(",");
                Self::diagnostics_start(&list)?;
                named(30, None, &list)
            }
            Self::NetworkCheck => Ok(vec![31]),
            Self::DiagnosticsReport { job, redact } => Ok(job_bytes(32, Some(*redact), *job)),
            Self::RepairFindings { job, findings } if *job > 0 => {
                let text = Self::findings_text(findings);
                Self::repair_findings(&job.to_string(), &text)?;
                let mut bytes = job_bytes(33, None, *job);
                bytes.extend_from_slice(text.as_bytes());
                Ok(bytes)
            }
            Self::MarkLogsSeen(job) if *job > 0 => Ok(job_bytes(34, None, *job)),
            Self::SetPeriodic { enabled, daily } => {
                Ok(vec![35, u8::from(*enabled), u8::from(*daily)])
            }
            Self::CleanupClean(ids) => {
                let list = ids.join(",");
                Self::cleanup_clean(&list)?;
                named(36, None, &list)
            }
            _ => Err(invalid()),
        }
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        fn text(bytes: &[u8]) -> io::Result<&str> {
            std::str::from_utf8(bytes).map_err(|_| invalid())
        }
        let flag_text = |flag: &u8| match flag {
            0 => Ok("false"),
            1 => Ok("true"),
            _ => Err(invalid()),
        };
        match bytes {
            [3] => Ok(Self::InstallNvidia),
            [9] => Ok(Self::UpdateAllNative),
            [12] => Ok(Self::ClearNativeCache),
            [code @ 20..=26] => ReadQuery::from_code(*code)
                .map(Self::Read)
                .ok_or_else(invalid),
            [1, name @ ..] => Self::install(text(name)?),
            [10, name @ ..] => Self::remove(text(name)?),
            [8, name @ ..] => Self::service_restart(text(name)?),
            [code @ (2 | 4), high, low, tcp @ (0 | 1)] => {
                let port = u16::from_be_bytes([*high, *low]);
                if port == 0 {
                    return Err(invalid());
                }
                let tcp = *tcp == 1;
                Ok(if *code == 2 {
                    Self::AddPort { port, tcp }
                } else {
                    Self::RemovePort { port, tcp }
                })
            }
            [5, flag, name @ ..] => Self::firewall_service(text(name)?, flag_text(flag)?),
            [6, flag, name @ ..] => Self::service_enabled(text(name)?, flag_text(flag)?),
            [7, flag, name @ ..] => Self::service_running(text(name)?, flag_text(flag)?),
            [11, flag, name @ ..] => Self::repo_enabled(text(name)?, flag_text(flag)?),
            [13, flag, name @ ..] => Self::set_admin(text(name)?, flag_text(flag)?),
            [14, flag, name @ ..] => Self::datetime(text(name)?, flag_text(flag)?),
            [30, list @ ..] => Self::diagnostics_start(text(list)?),
            [31] => Ok(Self::NetworkCheck),
            [32, flag, job @ ..] if job.len() == 4 => Self::diagnostics_report(
                &u32::from_be_bytes(job.try_into().map_err(|_| invalid())?).to_string(),
                flag_text(flag)?,
            ),
            [33, a, b, c, d, list @ ..] => Self::repair_findings(
                &u32::from_be_bytes([*a, *b, *c, *d]).to_string(),
                text(list)?,
            ),
            [34, a, b, c, d] => {
                Self::mark_logs_seen(&u32::from_be_bytes([*a, *b, *c, *d]).to_string())
            }
            [35, enabled, daily @ (0 | 1)] => Self::set_periodic(
                flag_text(enabled)?,
                if *daily == 1 { "daily" } else { "weekly" },
            ),
            [36, list @ ..] => Self::cleanup_clean(text(list)?),
            _ => Err(invalid()),
        }
    }
}

pub struct Request {
    pub username: String,
    pub password: Zeroizing<String>,
    pub session: [u8; 32],
    pub operation: Operation,
}

fn valid_credentials(username: &str, password: &str) -> bool {
    !username.is_empty()
        && username.len() <= crate::auth_ipc::MAX_USERNAME
        && !username.chars().any(char::is_control)
        && !password.is_empty()
        && password.len() <= crate::auth_ipc::MAX_PASSWORD
        && !password.contains('\0')
}

pub fn encode_request(request: &Request) -> io::Result<Zeroizing<Vec<u8>>> {
    if !valid_credentials(&request.username, &request.password) || request.session == [0; 32] {
        return Err(invalid());
    }
    let operation = request.operation.encode()?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        42 + request.username.len() + request.password.len() + operation.len(),
    ));
    bytes.extend_from_slice(MAGIC);
    for length in [
        request.username.len(),
        request.password.len(),
        operation.len(),
    ] {
        bytes.extend_from_slice(&(length as u16).to_be_bytes());
    }
    bytes.extend_from_slice(&request.session);
    bytes.extend_from_slice(request.username.as_bytes());
    bytes.extend_from_slice(request.password.as_bytes());
    bytes.extend_from_slice(&operation);
    Ok(bytes)
}

pub fn read_request(reader: &mut impl Read) -> io::Result<Request> {
    let mut header = [0; 42];
    reader.read_exact(&mut header)?;
    let user_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let password_len = u16::from_be_bytes([header[6], header[7]]) as usize;
    let operation_len = u16::from_be_bytes([header[8], header[9]]) as usize;
    if &header[..4] != MAGIC
        || !(1..=crate::auth_ipc::MAX_USERNAME).contains(&user_len)
        || !(1..=crate::auth_ipc::MAX_PASSWORD).contains(&password_len)
        || !(1..=MAX_OPERATION).contains(&operation_len)
        || header[10..] == [0; 32]
    {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(vec![0; user_len + password_len + operation_len]);
    reader.read_exact(&mut bytes)?;
    let username = std::str::from_utf8(&bytes[..user_len]).map_err(|_| invalid())?;
    let password =
        std::str::from_utf8(&bytes[user_len..user_len + password_len]).map_err(|_| invalid())?;
    if !valid_credentials(username, password) {
        return Err(invalid());
    }
    Ok(Request {
        username: username.to_owned(),
        password: Zeroizing::new(password.to_owned()),
        session: header[10..].try_into().map_err(|_| invalid())?,
        operation: Operation::decode(&bytes[user_len + password_len..])?,
    })
}

/// The helper owns the associated account/session/operation; COMMIT cannot
/// replace those fields. A grant is scoped to this one connection and read once.
pub fn read_commit(reader: &mut impl Read, grant: &[u8; 32]) -> io::Result<()> {
    let mut bytes = [0; 36];
    reader.read_exact(&mut bytes)?;
    let difference = bytes[4..]
        .iter()
        .zip(grant)
        .fold(0, |diff, (a, b)| diff | (a ^ b));
    if &bytes[..4] != COMMIT || difference != 0 {
        return Err(invalid());
    }
    // A half-close terminates the sole commit. Trailing bytes or batched
    // requests are refused before the worker or any D-Bus call is created.
    if reader.read(&mut [0])? != 0 {
        return Err(invalid());
    }
    Ok(())
}

pub fn write_prepared(
    writer: &mut impl Write,
    grant: &[u8; 32],
    audit: &[u8; 16],
) -> io::Result<()> {
    writer.write_all(&[0])?;
    writer.write_all(grant)?;
    writer.write_all(audit)
}

pub fn write_result(writer: &mut impl Write, transaction: u32, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(invalid());
    }
    writer.write_all(&[0])?;
    writer.write_all(&transaction.to_be_bytes())?;
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)
}

pub struct Completed {
    pub transaction: u32,
    pub payload: Vec<u8>,
    pub audit_id: String,
}

/// Cancellation drops this future and its only socket, revoking the pending
/// request. Once COMMIT reaches the broker, the daemon may have accepted work;
/// disconnecting cannot promise that an already-started operation was undone.
pub async fn execute(path: &Path, request: Request) -> io::Result<Completed> {
    tokio::time::timeout(CLIENT_TIMEOUT, async {
        let frame = encode_request(&request)?;
        drop(request);
        let mut socket = tokio::net::UnixStream::connect(path).await?;
        if socket.peer_cred()?.uid() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker peer is not root",
            ));
        }
        socket.write_all(&frame).await?;
        drop(frame);
        if socket.read_u8().await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reauthentication rejected",
            ));
        }
        let mut grant = Zeroizing::new([0u8; 32]);
        let mut audit = [0u8; 16];
        socket.read_exact(grant.as_mut()).await?;
        socket.read_exact(&mut audit).await?;
        // Give the enclosing session-revocation select a checkpoint before
        // consuming the grant, even when all local socket I/O was ready.
        tokio::task::yield_now().await;
        socket.write_all(COMMIT).await?;
        socket.write_all(grant.as_ref()).await?;
        socket.shutdown().await?;
        if socket.read_u8().await? != 0 {
            return Err(io::Error::other("operation rejected or failed"));
        }
        let transaction = socket.read_u32().await?;
        let length = socket.read_u32().await? as usize;
        if length > MAX_PAYLOAD {
            return Err(invalid());
        }
        let mut payload = vec![0u8; length];
        socket.read_exact(&mut payload).await?;
        if socket.read(&mut [0]).await? != 0 {
            return Err(invalid());
        }
        Ok(Completed {
            transaction,
            payload,
            audit_id: audit.iter().map(|byte| format!("{byte:02x}")).collect(),
        })
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "administrative request timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvidia_is_a_distinct_parameter_free_operation() {
        let operation = Operation::InstallNvidia;
        assert_eq!(
            Operation::decode(&operation.encode().unwrap()).unwrap(),
            operation
        );
        assert_eq!(operation.action_id(), "org.lyraos.vega.software.install");
        for forged in [&[3, 0][..], &[3, 1][..], &[3, b'-', b'f'][..]] {
            assert!(Operation::decode(forged).is_err())
        }
        let frame = encode_request(&request(operation.clone())).unwrap();
        let parsed = read_request(&mut frame.as_slice()).unwrap();
        assert_eq!(parsed.operation, operation);
        assert_eq!(parsed.session, [7; 32]);
    }

    fn request(operation: Operation) -> Request {
        Request {
            username: "alice".into(),
            password: Zeroizing::new("test-only".into()),
            session: [7; 32],
            operation,
        }
    }

    #[test]
    fn operations_are_native_names_and_single_tcp_udp_ports_only() {
        for name in ["kernel-default", "libstdc++6", "python3.12", "example_1"] {
            let operation = Operation::install(name).unwrap();
            assert_eq!(
                Operation::decode(&operation.encode().unwrap()).unwrap(),
                operation
            );
        }
        for name in [
            "",
            "-kernel",
            "--repo",
            "pkg=1",
            "repo:pkg",
            "*.rpm",
            "x y",
            "x;y",
            "/tmp/pkg.rpm",
            "https://example/x",
            "pkg\n",
        ] {
            assert!(Operation::install(name).is_err(), "{name:?}");
        }
        for (port, protocol) in [("1", "tcp"), ("65535", "udp")] {
            let operation = Operation::port(port, protocol).unwrap();
            assert_eq!(
                Operation::decode(&operation.encode().unwrap()).unwrap(),
                operation
            );
        }
        for (port, protocol) in [
            ("0", "tcp"),
            ("65536", "udp"),
            ("1-2", "tcp"),
            ("+1", "tcp"),
            ("1", "sctp"),
        ] {
            assert!(Operation::port(port, protocol).is_err());
        }
    }

    #[test]
    fn every_operation_round_trips_with_its_action_and_rejects_forged_parameters() {
        let operations = [
            Operation::remove_port("8443", "udp").unwrap(),
            Operation::firewall_service("ssh", "true").unwrap(),
            Operation::firewall_service("dhcpv6-client", "false").unwrap(),
            Operation::service_enabled("sshd.service", "false").unwrap(),
            Operation::service_running("vega-web.service", "true").unwrap(),
            Operation::service_restart("getty@tty1.service").unwrap(),
            Operation::UpdateAllNative,
            Operation::remove("libstdc++6").unwrap(),
            Operation::repo_enabled("repo-oss", "false").unwrap(),
            Operation::repo_enabled("home:user:project", "true").unwrap(),
            Operation::ClearNativeCache,
            Operation::set_admin("rbrito", "true").unwrap(),
            Operation::datetime("America/Sao_Paulo", "true").unwrap(),
            Operation::datetime("UTC", "false").unwrap(),
            Operation::datetime("Etc/GMT+3", "true").unwrap(),
            Operation::Read(ReadQuery::KernelBoot),
            Operation::Read(ReadQuery::Firewall),
        ];
        for operation in operations {
            let encoded = operation.encode().unwrap();
            assert!(encoded.len() <= MAX_OPERATION, "{operation:?}");
            assert_eq!(Operation::decode(&encoded).unwrap(), operation);
            assert!(operation.action_id().starts_with("org.lyraos.vega."));
            assert!(operation.return_href().starts_with('/'));
            assert!(!operation.describe().is_empty());
            let frame = encode_request(&request(operation.clone())).unwrap();
            assert_eq!(
                read_request(&mut frame.as_slice()).unwrap().operation,
                operation
            );
        }
        assert!(
            Operation::service_restart("sshd").is_err(),
            "unit suffix required"
        );
        assert!(Operation::service_restart("../etc.service").is_err());
        assert!(Operation::service_running("sshd.service", "yes").is_err());
        assert!(Operation::firewall_service("ssh;rm", "true").is_err());
        assert!(Operation::repo_enabled("repo oss", "true").is_err());
        assert!(Operation::set_admin("Root", "true").is_err());
        assert!(Operation::set_admin("a-very-long-user-name-beyond-posix-limits", "true").is_err());
        assert!(Operation::datetime("America//Sao_Paulo", "true").is_err());
        assert!(Operation::datetime("../zoneinfo", "true").is_err());
        assert!(Operation::remove_port("0", "tcp").is_err());
        for forged in [
            &[5u8, 2, b's'][..],
            &[6, 1][..],
            &[14, 1][..],
            &[13, 0, b'R'][..],
            &[15][..],
            &[27][..],
            &[20, 0][..],
        ] {
            assert!(Operation::decode(forged).is_err(), "{forged:?}");
        }
    }

    #[test]
    fn diagnostics_and_cleanup_operations_round_trip_with_fixed_fields_only() {
        let operations = [
            Operation::diagnostics_start(
                "packages,disk-health,logs,platform,security,boot,network",
            )
            .unwrap(),
            Operation::diagnostics_start("cpu-stress").unwrap(),
            Operation::NetworkCheck,
            Operation::diagnostics_report("42", "false").unwrap(),
            Operation::diagnostics_report("4294967295", "true").unwrap(),
            Operation::repair_findings("7", "logs:0,security:2,network:10").unwrap(),
            Operation::repair_findings(
                "7",
                "packages:0,packages:1,packages:2,packages:3,disk-health:0,disk-health:1,\
                 memory-stress:0,memory-stress:1,cpu-stress:0,disk-bench:0,platform:0,\
                 platform:999,security:0,security:1,network:0,boot:0",
            )
            .unwrap(),
            Operation::mark_logs_seen("9").unwrap(),
            Operation::set_periodic("true", "daily").unwrap(),
            Operation::set_periodic("false", "weekly").unwrap(),
            Operation::cleanup_clean("journal,package-cache").unwrap(),
            Operation::cleanup_clean(
                "coredumps,journal,package-cache,flatpak-unused,old-kernels,snapshots",
            )
            .unwrap(),
            Operation::Read(ReadQuery::LastPeriodic),
            Operation::Read(ReadQuery::CleanupScan),
        ];
        for operation in operations {
            let encoded = operation.encode().unwrap();
            assert!(encoded.len() <= MAX_OPERATION, "{operation:?}");
            assert_eq!(Operation::decode(&encoded).unwrap(), operation);
            assert!(operation.action_id().starts_with("org.lyraos.vega."));
            assert!(operation.return_href().starts_with('/'));
            assert!(!operation.describe().is_empty());
            let frame = encode_request(&request(operation.clone())).unwrap();
            assert_eq!(
                read_request(&mut frame.as_slice()).unwrap().operation,
                operation
            );
        }
        assert_eq!(
            Operation::NetworkCheck.action_id(),
            "org.lyraos.vega.network.diagnose"
        );
        for tests in [
            "",
            "network",
            "../../etc",
            "logs,logs",
            "logs,",
            "Logs",
            "gpu",
        ] {
            assert!(Operation::diagnostics_start(tests).is_err(), "{tests:?}");
        }
        for job in ["", "0", "-1", "1e3", "4294967296", " 1", "00"] {
            assert!(Operation::mark_logs_seen(job).is_err(), "{job:?}");
            if job != "0" {
                assert!(
                    Operation::diagnostics_report(job, "true").is_err(),
                    "{job:?}"
                );
            }
        }
        let latest = Operation::diagnostics_report("0", "false").unwrap();
        assert_eq!(
            Operation::decode(&latest.encode().unwrap()).unwrap(),
            latest
        );
        for findings in [
            "",
            "logs",
            "logs:",
            "logs:1000",
            "logs:-1",
            "logs:0,logs:0",
            "etc:0",
            "logs:0;security:1",
        ] {
            assert!(
                Operation::repair_findings("1", findings).is_err(),
                "{findings:?}"
            );
        }
        let seventeen: Vec<String> = (0..17).map(|i| format!("logs:{i}")).collect();
        assert!(Operation::repair_findings("1", &seventeen.join(",")).is_err());
        assert!(Operation::set_periodic("true", "monthly").is_err());
        assert!(Operation::set_periodic("yes", "weekly").is_err());
        for categories in ["", "home-cache", "journal,journal", "trash", "journal;rm"] {
            assert!(
                Operation::cleanup_clean(categories).is_err(),
                "{categories:?}"
            );
        }
        for forged in [
            &[30u8][..],
            &[30, b'n', b'e', b't', b'w', b'o', b'r', b'k'][..],
            &[31, 0][..],
            &[32, 2, 0, 0, 0, 1][..],
            &[32, 0, 0, 0, 1][..],
            &[33, 0, 0, 0, 1][..],
            &[34, 0, 0, 0, 0][..],
            &[35, 1, 2][..],
            &[36, b'x'][..],
            &[27][..],
        ] {
            assert!(Operation::decode(forged).is_err(), "{forged:?}");
        }
    }

    #[test]
    fn bounded_frames_reject_truncation_oversize_invalid_utf8_and_unknown_operations() {
        let request = request(Operation::install("example").unwrap());
        let frame = encode_request(&request).unwrap();
        let parsed = read_request(&mut frame.as_slice()).unwrap();
        assert_eq!(parsed.operation, request.operation);
        assert_eq!(parsed.session, request.session);
        for length in 0..frame.len() {
            assert!(
                read_request(&mut &frame[..length]).is_err(),
                "length {length}"
            );
        }
        for (index, value) in [
            (0, 0),
            (4, 255),
            (6, 255),
            (8, 255),
            (42, 0),
            (42, 255),
            (frame.len() - 8, 9),
        ] {
            let mut broken = frame.to_vec();
            broken[index] = value;
            assert!(
                read_request(&mut broken.as_slice()).is_err(),
                "offset {index}"
            );
        }
        let mut broken = frame.to_vec();
        broken[10..42].fill(0);
        assert!(read_request(&mut broken.as_slice()).is_err());
    }

    #[test]
    fn commits_cannot_replay_a_grant_from_another_connection_or_append_parameters() {
        let mut commit = COMMIT.to_vec();
        commit.extend_from_slice(&[1; 32]);
        assert!(read_commit(&mut commit.as_slice(), &[1; 32]).is_ok());
        assert!(read_commit(&mut commit.as_slice(), &[2; 32]).is_err());
        for length in 0..commit.len() {
            assert!(read_commit(&mut &commit[..length], &[1; 32]).is_err());
        }
        let mut replay = commit.clone();
        replay.extend_from_slice(&commit);
        assert!(read_commit(&mut replay.as_slice(), &[1; 32]).is_err());
    }
}
