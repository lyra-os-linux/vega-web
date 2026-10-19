//! A PAM-authenticated, single-use operation over a peer-checked Unix socket.
//! The grant never reaches the browser. Dropping the client connection revokes
//! an unconsumed grant; a committed daemon transaction must finish normally.
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const GRANT_TIMEOUT: Duration = Duration::from_secs(10);
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(70);
const MAGIC: &[u8; 4] = b"VWA1";
const COMMIT: &[u8; 4] = b"VWC1";
// Longest operation frame: one code byte, one flag byte and a 200-byte name.
const MAX_OPERATION: usize = 202;
const MAX_NAME: usize = 200;

/// One administrative operation, authorized by the user's own password through
/// the root broker and executed by vegad with the user's identity. Each variant
/// maps to exactly one polkit action; the wire encoding is a code byte followed
/// by fixed fields, with no free-form parsing on the privileged side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    InstallNative(String),
    InstallNvidia,
    AddPort { port: u16, tcp: bool },
    RemovePort { port: u16, tcp: bool },
    FirewallService { name: String, enabled: bool },
    ServiceEnabled { name: String, enabled: bool },
    ServiceRunning { name: String, running: bool },
    ServiceRestart(String),
    UpdateAllNative,
    RemoveNative(String),
    RepoEnabled { name: String, enabled: bool },
    ClearNativeCache,
    SetAdmin { username: String, admin: bool },
    DateTime { timezone: String, ntp: bool },
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

impl Operation {
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
            Self::AddPort { .. } | Self::RemovePort { .. } | Self::FirewallService { .. } => "/rede",
            Self::ServiceEnabled { .. } | Self::ServiceRunning { .. } | Self::ServiceRestart(_) => {
                "/servicos"
            }
            Self::SetAdmin { .. } => "/usuarios",
            Self::DateTime { .. } => "/data-hora",
        }
    }

    /// Human description (pt-BR) for the confirmation dialog and the result page.
    pub fn describe(&self) -> String {
        let proto = |tcp: &bool| if *tcp { "tcp" } else { "udp" };
        match self {
            Self::InstallNative(name) => format!("Instalar o pacote {name}"),
            Self::InstallNvidia => "Instalar o driver NVIDIA oficial".to_owned(),
            Self::AddPort { port, tcp } => format!("Abrir a porta {port}/{} no firewall", proto(tcp)),
            Self::RemovePort { port, tcp } => {
                format!("Fechar a porta {port}/{} no firewall", proto(tcp))
            }
            Self::FirewallService { name, enabled: true } => {
                format!("Permitir o serviço {name} no firewall")
            }
            Self::FirewallService { name, enabled: false } => {
                format!("Bloquear o serviço {name} no firewall")
            }
            Self::ServiceEnabled { name, enabled: true } => {
                format!("Habilitar {name} na inicialização")
            }
            Self::ServiceEnabled { name, enabled: false } => {
                format!("Desabilitar {name} na inicialização")
            }
            Self::ServiceRunning { name, running: true } => format!("Iniciar {name}"),
            Self::ServiceRunning { name, running: false } => format!("Parar {name}"),
            Self::ServiceRestart(name) => format!("Reiniciar {name}"),
            Self::UpdateAllNative => "Aplicar todas as atualizações disponíveis".to_owned(),
            Self::RemoveNative(name) => format!("Remover o pacote {name}"),
            Self::RepoEnabled { name, enabled: true } => format!("Habilitar o repositório {name}"),
            Self::RepoEnabled { name, enabled: false } => {
                format!("Desabilitar o repositório {name}")
            }
            Self::ClearNativeCache => "Limpar o cache de pacotes".to_owned(),
            Self::SetAdmin { username, admin: true } => {
                format!("Tornar {username} administrador")
            }
            Self::SetAdmin { username, admin: false } => {
                format!("Retirar {username} dos administradores")
            }
            Self::DateTime { timezone, ntp } => format!(
                "Definir o fuso horário {timezone} e {} a sincronização automática (NTP)",
                if *ntp { "ativar" } else { "desativar" }
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
                let mut bytes = vec![if matches!(self, Self::AddPort { .. }) { 2 } else { 4 }];
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
            Self::SetAdmin { username, admin } => {
                Self::set_admin(username, "true")?;
                named(13, Some(*admin), username)
            }
            Self::DateTime { timezone, ntp } => {
                Self::datetime(timezone, "true")?;
                named(14, Some(*ntp), timezone)
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

pub fn write_result(writer: &mut impl Write, transaction: u32) -> io::Result<()> {
    writer.write_all(&[0])?;
    writer.write_all(&transaction.to_be_bytes())
}

pub struct Completed {
    pub transaction: u32,
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
        if socket.read(&mut [0]).await? != 0 {
            return Err(invalid());
        }
        Ok(Completed {
            transaction,
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
