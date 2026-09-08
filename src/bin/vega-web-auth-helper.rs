//! One PAM authentication/account check, launched as root by systemd. All
//! untrusted input arrives over the peer-checked, bounded local protocol.
#[path = "../pam_ffi.rs"]
mod pam_ffi;

use std::ffi::CString;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use vega_web::auth_ipc::{self, DeadlineStream, REQUEST_TIMEOUT};

fn main() {
    if run().is_err() {
        // Do not expose passwords, frames or PAM module diagnostics in logs.
        eprintln!("vega-web-auth-helper: authentication request rejected");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args()
        .collect::<Vec<_>>()
        .get(1..)
        .unwrap_or_default()
        != ["--socket"]
        || unsafe { libc::geteuid() } != 0
    {
        return Err("socket activation as root required".into());
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let name = CString::new("vega-web")?;
    // Single-threaded helper; copy the UID before calling any other NSS API.
    let account = unsafe { libc::getpwnam(name.as_ptr()) };
    if account.is_null() {
        return Err("service account missing".into());
    }
    let uid = unsafe { (*account).pw_uid };
    if uid == 0 || auth_ipc::peer_uid(0)? != uid {
        return Err("untrusted peer".into());
    }
    let socket = unsafe { UnixStream::from_raw_fd(0) };
    let output = socket.try_clone()?;
    let mut request_stream = DeadlineStream::new(socket, REQUEST_TIMEOUT);
    let credentials = auth_ipc::read_request(&mut request_stream)?;
    // The PAM service is fixed here; root administrators configure its stack
    // in /etc/pam.d/vega-web. The network process cannot select another stack.
    let result = pam_ffi::authenticate("vega-web", &credentials.username, &credentials.password);
    drop(credentials);
    let mut output = DeadlineStream::new(output, REQUEST_TIMEOUT);
    output.write_all(&[u8::from(result.is_err())])?;
    result.map_err(|error| error.into())
}
