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
const MAX_OPERATION: usize = 201;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    InstallNative(String),
    AddPort { port: u16, tcp: bool },
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid administrative frame")
}

impl Operation {
    pub fn install(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() > 200
            || !name.as_bytes()[0].is_ascii_alphanumeric()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+_.-".contains(&byte))
        {
            return Err(invalid());
        }
        Ok(Self::InstallNative(name.to_owned()))
    }

    pub fn port(port: &str, protocol: &str) -> io::Result<Self> {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let port: u16 = port.parse().map_err(|_| invalid())?;
        if port == 0 || !matches!(protocol, "tcp" | "udp") {
            return Err(invalid());
        }
        Ok(Self::AddPort {
            port,
            tcp: protocol == "tcp",
        })
    }

    pub fn action_id(&self) -> &'static str {
        match self {
            Self::InstallNative(_) => "org.lyraos.vega.software.install",
            Self::AddPort { .. } => "org.lyraos.vega.firewall.configure",
        }
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        match self {
            Self::InstallNative(name) => {
                Self::install(name)?;
                let mut bytes = vec![1];
                bytes.extend_from_slice(name.as_bytes());
                Ok(bytes)
            }
            Self::AddPort { port, tcp } if *port > 0 => {
                let mut bytes = vec![2];
                bytes.extend_from_slice(&port.to_be_bytes());
                bytes.push(u8::from(*tcp));
                Ok(bytes)
            }
            _ => Err(invalid()),
        }
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        match bytes {
            [1, name @ ..] => Self::install(std::str::from_utf8(name).map_err(|_| invalid())?),
            [2, high, low, tcp @ (0 | 1)] => {
                let port = u16::from_be_bytes([*high, *low]);
                if port == 0 {
                    return Err(invalid());
                }
                Ok(Self::AddPort {
                    port,
                    tcp: *tcp == 1,
                })
            }
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
