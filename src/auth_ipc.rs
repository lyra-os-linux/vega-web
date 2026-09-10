//! A single bounded authentication request per local connection. Neither
//! service names, commands nor filesystem paths are accepted from the peer.
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"VPA1";
pub const MAX_USERNAME: usize = 256;
pub const MAX_PASSWORD: usize = 4096;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(35);

pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid authentication frame")
}

fn valid(username: &str, password: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME
        && !username.chars().any(char::is_control)
        && !password.is_empty()
        && password.len() <= MAX_PASSWORD
        && !password.contains('\0')
}

pub fn write_request(writer: &mut impl Write, username: &str, password: &str) -> io::Result<()> {
    if !valid(username, password) {
        return Err(invalid());
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(8 + username.len() + password.len()));
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&(username.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(password.len() as u16).to_be_bytes());
    frame.extend_from_slice(username.as_bytes());
    frame.extend_from_slice(password.as_bytes());
    writer.write_all(&frame)
}

pub fn read_request(reader: &mut impl Read) -> io::Result<Credentials> {
    let mut header = [0; 8];
    reader.read_exact(&mut header)?;
    let username_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let password_len = u16::from_be_bytes([header[6], header[7]]) as usize;
    if &header[..4] != MAGIC
        || !(1..=MAX_USERNAME).contains(&username_len)
        || !(1..=MAX_PASSWORD).contains(&password_len)
    {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(vec![0; username_len + password_len]);
    reader.read_exact(&mut bytes)?;
    // Half-close terminates the request; reject batching and trailing data.
    if reader.read(&mut [0])? != 0 {
        return Err(invalid());
    }
    let username = std::str::from_utf8(&bytes[..username_len]).map_err(|_| invalid())?;
    let password = std::str::from_utf8(&bytes[username_len..]).map_err(|_| invalid())?;
    if !valid(username, password) {
        return Err(invalid());
    }
    Ok(Credentials {
        username: username.to_string(),
        password: Zeroizing::new(password.to_string()),
    })
}

pub fn peer_uid(fd: RawFd) -> io::Result<libc::uid_t> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::ucred>() {
        return Err(invalid());
    }
    Ok(credentials.uid)
}

/// Connect without waiting on a full local listen backlog. A busy helper fails
/// closed; socket read/write timeouts alone would not bound blocking connect().
fn connect(path: &Path) -> io::Result<UnixStream> {
    let path = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.len() >= address.sun_path.len() || path.contains(&0) {
        return Err(invalid());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in address.sun_path.iter_mut().zip(path) {
        *dst = *src as libc::c_char;
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// Recomputes the remaining total deadline on every read/write, including
/// partial I/O. A peer cannot prolong the request by dripping bytes.
pub struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}

impl DeadlineStream {
    pub fn new(stream: UnixStream, timeout: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + timeout,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "authentication deadline exceeded")
            })
    }

    pub fn finish_request(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn authenticate(path: &Path, username: &str, password: &str) -> io::Result<()> {
    if !valid(username, password) {
        return Err(invalid());
    }
    let stream = connect(path)?;
    if peer_uid(stream.as_raw_fd())? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authentication peer is not root",
        ));
    }
    let mut stream = DeadlineStream::new(stream, CLIENT_TIMEOUT);
    write_request(&mut stream, username, password)?;
    stream.finish_request()?;
    let mut response = [0xff];
    stream.read_exact(&mut response)?;
    if response != [0] || stream.read(&mut [0])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authentication rejected",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_reject_truncation_oversize_invalid_text_and_extra_requests() {
        let mut frame = Vec::new();
        write_request(&mut frame, "alice", "password").unwrap();
        let parsed = read_request(&mut frame.as_slice()).unwrap();
        assert_eq!(parsed.username, "alice");
        assert_eq!(*parsed.password, "password");
        for length in 0..frame.len() {
            assert!(read_request(&mut &frame[..length]).is_err());
        }
        let mut extra = frame.clone();
        extra.extend_from_slice(&frame);
        assert!(read_request(&mut extra.as_slice()).is_err());
        for (index, byte) in [(0, b'X'), (4, 255), (6, 255), (8, 0), (8, 255), (13, 0)] {
            let mut invalid = frame.clone();
            invalid[index] = byte;
            assert!(read_request(&mut invalid.as_slice()).is_err());
        }
        for (user, password) in [
            ("", "password"),
            ("alice\n", "password"),
            ("alice", ""),
            ("alice", "x\0y"),
        ] {
            assert!(write_request(&mut Vec::new(), user, password).is_err());
        }
        assert!(write_request(&mut Vec::new(), "alice", &"x".repeat(MAX_PASSWORD + 1)).is_err());
    }
}
