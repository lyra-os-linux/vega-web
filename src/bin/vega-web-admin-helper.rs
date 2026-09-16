//! One root-owned PAM grant, followed by exactly one D-Bus call as its user.
//! No shell command, service name, environment or identity chosen by a browser.
#[path = "../admin_polkit.rs"]
mod admin_polkit;
#[path = "../pam_ffi.rs"]
mod pam_ffi;

use lyra_vega_dbus::{FirewallClient, SoftwareClient, VegaDbus};
use rand::RngExt;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::ptr;
use std::time::Duration;
use vega_web::admin_ipc::{self, Operation};
use vega_web::auth_ipc::{self, DeadlineStream};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    if run().is_err() {
        // The internal reason, PAM responses and opaque grants never enter logs.
        eprintln!("vega-web-admin-helper: request rejected or failed");
        let _ = io::stdout().write_all(&[1]);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("root socket activation required".into());
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [mode] if mode == "--socket" => broker(),
        [mode] if mode == "--worker" => worker(),
        _ => Err("invalid activation mode".into()),
    }
}

fn service_uid() -> Result<libc::uid_t> {
    let name = CString::new("vega-web")?;
    let user = unsafe { libc::getpwnam(name.as_ptr()) };
    if user.is_null() || unsafe { (*user).pw_uid } == 0 {
        return Err("missing service account".into());
    }
    Ok(unsafe { (*user).pw_uid })
}

#[derive(PartialEq, Eq)]
struct Account {
    name: CString,
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

fn account(name: &str) -> Result<Account> {
    let cname = CString::new(name)?;
    let user = unsafe { libc::getpwnam(cname.as_ptr()) };
    if user.is_null() || unsafe { (*user).pw_name }.is_null() {
        return Err("account missing".into());
    }
    let (uid, gid, canonical) = unsafe {
        (
            (*user).pw_uid,
            (*user).pw_gid,
            CStr::from_ptr((*user).pw_name).to_owned(),
        )
    };
    if canonical != cname || uid == 0 || uid == service_uid()? {
        return Err("account is not eligible".into());
    }
    let wheel = unsafe { libc::getgrnam(c"wheel".as_ptr()) };
    if wheel.is_null() {
        return Err("administrative group missing".into());
    }
    let wheel_gid = unsafe { (*wheel).gr_gid };
    let mut count = 0;
    unsafe {
        libc::getgrouplist(cname.as_ptr(), gid, ptr::null_mut(), &mut count);
    }
    if !(1..=65536).contains(&count) {
        return Err("invalid group count".into());
    }
    let mut groups = vec![0; count as usize];
    if unsafe { libc::getgrouplist(cname.as_ptr(), gid, groups.as_mut_ptr(), &mut count) } < 0 {
        return Err("groups changed".into());
    }
    groups.truncate(count as usize);
    groups.sort_unstable();
    groups.dedup();
    if !groups.contains(&wheel_gid) {
        return Err("administrator required".into());
    }
    Ok(Account {
        name: cname,
        uid,
        gid,
        groups,
    })
}

fn broker() -> Result<()> {
    if auth_ipc::peer_uid(0)? != service_uid()? {
        return Err("untrusted peer".into());
    }
    let socket = unsafe { UnixStream::from_raw_fd(0) };
    let output = socket.try_clone()?;
    let mut input = DeadlineStream::new(socket, admin_ipc::REQUEST_TIMEOUT);
    let request = admin_ipc::read_request(&mut input)?;
    let mut audit = [0u8; 16];
    rand::rng().fill(&mut audit);
    let audit_id: String = audit.iter().map(|byte| format!("{byte:02x}")).collect();
    // Debug quoting prevents log injection; operation validation excludes
    // control characters and secrets. 'claimed_user' is not an authorized UID.
    eprintln!(
        "vega-web-admin: id={audit_id} claimed_user={:?} action={} operation={:?} phase=requested",
        request.username,
        request.operation.action_id(),
        request.operation
    );
    let mut committed = false;
    let outcome = (|| -> Result<u32> {
        let mut pam = pam_ffi::AuthenticatedAccount::authenticate(
            "vega-web",
            &request.username,
            &request.password,
        )?;
        let user = account(&request.username)?;
        // All associated fields stay in this one process/connection. Neither
        // the commit nor a subsequent connection can replace them.
        let mut grant = Zeroizing::new([0u8; 32]);
        rand::rng().fill(grant.as_mut());
        let mut output = DeadlineStream::new(output, admin_ipc::REQUEST_TIMEOUT);
        admin_ipc::write_prepared(&mut output, &grant, &audit)?;
        let mut input = DeadlineStream::new(input.into_inner(), admin_ipc::GRANT_TIMEOUT);
        admin_ipc::read_commit(&mut input, &grant)?;
        pam.check_account()?;
        if account(&request.username)? != user {
            return Err("account changed".into());
        }
        drop(pam);
        committed = true;
        let operation = request.operation.clone();
        // This is the only place the worker can be started. Grants are never
        // persisted/reused, and no operation exists on a disconnected prepare.
        eprintln!(
            "vega-web-admin: id={audit_id} user={:?} uid={} action={} phase=committed",
            request.username,
            user.uid,
            operation.action_id()
        );
        drop(request);
        drop(grant);
        let transaction = start_worker(&user, &operation, &audit_id)?;
        eprintln!("vega-web-admin: id={audit_id} phase=accepted transaction={transaction}");
        let mut output = DeadlineStream::new(output.into_inner(), admin_ipc::REQUEST_TIMEOUT);
        if admin_ipc::write_result(&mut output, transaction).is_err() {
            eprintln!(
                "vega-web-admin: id={audit_id} phase=response-undelivered transaction={transaction}"
            );
        }
        Ok(transaction)
    })();
    match &outcome {
        Ok(_) => {}
        Err(_) => eprintln!(
            "vega-web-admin: id={audit_id} phase={}",
            if committed {
                "outcome-unconfirmed"
            } else {
                "rejected"
            }
        ),
    }
    outcome.map(|_| ())
}

fn start_worker(user: &Account, operation: &Operation, audit: &str) -> Result<u32> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_worker(user, operation, audit))
}

async fn run_worker(user: &Account, operation: &Operation, audit: &str) -> Result<u32> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Exec while still root, then drop identity inside the fresh process.
    // Exec after setuid would reset dumpability and expose a privileged caller
    // to other processes of the account before main could disable ptracing.
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .arg("--worker")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let pid = child.id().ok_or("worker PID missing")?;
    let mut input = child.stdin.take().ok_or("worker stdin missing")?;
    let mut output = child.stdout.take().ok_or("worker stdout missing")?;
    let mut frame = user.uid.to_be_bytes().to_vec();
    frame.extend_from_slice(&(user.name.as_bytes().len() as u16).to_be_bytes());
    frame.extend_from_slice(user.name.as_bytes());
    frame.extend_from_slice(&operation.encode()?);
    input.write_all(&(frame.len() as u16).to_be_bytes()).await?;
    input.write_all(&frame).await?;
    let mut ready = [0];
    tokio::time::timeout(Duration::from_secs(5), output.read_exact(&mut ready)).await??;
    if ready != [2] {
        return Err("worker did not drop identity".into());
    }
    let (connection, subject) = tokio::time::timeout(
        Duration::from_secs(5),
        admin_polkit::register(pid, user.uid, operation.action_id(), audit),
    )
    .await??;
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        input.write_all(&[3]).await?;
        let mut result = [0u8; 5];
        output.read_exact(&mut result).await?;
        if result[0] != 0 {
            return Err("worker rejected or failed".into());
        }
        Ok::<_, Box<dyn std::error::Error>>(u32::from_be_bytes(result[1..].try_into()?))
    })
    .await;
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        admin_polkit::unregister(&connection, &subject),
    )
    .await;
    // The worker waits for this EOF before exiting, keeping its PID owned
    // until its per-process authentication agent has been removed.
    drop(input);
    let transaction = outcome??;
    if !tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await??
        .success()
    {
        return Err("worker exited unsuccessfully".into());
    }
    Ok(transaction)
}

fn worker() -> Result<()> {
    let mut length = [0u8; 2];
    io::stdin().read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    if !(8..=463).contains(&length) {
        return Err("invalid worker request".into());
    }
    let mut frame = vec![0u8; length];
    io::stdin().read_exact(&mut frame)?;
    let uid = u32::from_be_bytes(frame[..4].try_into()?);
    let length = u16::from_be_bytes(frame[4..6].try_into()?) as usize;
    if !(1..=256).contains(&length) || frame.len() <= 6 + length {
        return Err("invalid worker identity".into());
    }
    let user = account(std::str::from_utf8(&frame[6..6 + length])?)?;
    if user.uid != uid {
        return Err("account identity changed".into());
    }
    let operation = Operation::decode(&frame[6 + length..])?;
    // No fork/exec after dropping identity. No shell, session bus, HOME, locale
    // path, or other caller-controlled environment reaches the D-Bus client.
    if unsafe { libc::setgroups(user.groups.len(), user.groups.as_ptr()) } != 0
        || unsafe { libc::setresgid(user.gid, user.gid, user.gid) } != 0
        || unsafe { libc::setresuid(user.uid, user.uid, user.uid) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::geteuid() } != uid
    {
        return Err(io::Error::last_os_error().into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let transaction = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let dbus = VegaDbus::connect().await?;
            io::stdout().write_all(&[2])?;
            io::stdout().flush()?;
            let mut commit = [0];
            io::stdin().read_exact(&mut commit)?;
            if commit != [3] {
                return Err("worker not committed".into());
            }
            match operation {
                Operation::InstallNvidia => Ok(dbus.software().install_nvidia(true).await?),
                Operation::InstallNative(name) => Ok::<_, Box<dyn std::error::Error>>(
                    dbus.software().install("official", &name).await?,
                ),
                Operation::AddPort { port, tcp } => {
                    dbus.firewall()
                        .add_port(&port.to_string(), if tcp { "tcp" } else { "udp" })
                        .await?;
                    Ok(0)
                }
            }
        })
        .await?
    })?;
    admin_ipc::write_result(&mut io::stdout(), transaction)?;
    io::stdout().flush()?;
    if io::stdin().read(&mut [0])? != 0 {
        return Err("trailing worker command".into());
    }
    Ok(())
}
