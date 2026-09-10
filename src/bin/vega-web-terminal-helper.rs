//! Broker root ativado por socket do terminal web. Não aceita comandos: abre
//! apenas o shell cadastrado, depois de validar o peer e o grupo wheel.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::RawFd;
use std::ptr;

const MAX_INPUT: usize = 64 * 1024;

#[derive(Clone)]
struct Account {
    name: CString,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: CString,
    shell: CString,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("vega-web-terminal-helper: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    parse_mode()?;
    let caller = account("vega-web")?;
    if unsafe { libc::geteuid() } != 0 || peer_uid(0)? != caller.uid {
        return Err("só aceita conexões do usuário de serviço vega-web".into());
    }

    let username = read_username(0).map_err(|error| format!("identidade inválida: {error}"))?;
    let target = account(&username)?;
    if target.uid == 0 {
        return Err("login root não é permitido no terminal web".into());
    }
    if !is_wheel_member(&target)? {
        return Err("usuário não pertence ao grupo wheel".into());
    }

    let mut master: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pid = unsafe { libc::forkpty(&mut master, ptr::null_mut(), ptr::null(), &size) };
    if pid < 0 {
        return Err(format!("forkpty falhou: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        child_exec(&target);
    }

    // Only the byte-forwarding child parses terminal frames, as vega-web.
    // A small root supervisor must remain able to signal the other user's
    // shell. It only observes disconnects, child exits and wheel membership.
    let broker = unsafe { libc::fork() };
    if broker == 0 {
        if unsafe { libc::setgroups(1, &caller.gid) } != 0
            || unsafe { libc::setgid(caller.gid) } != 0
            || unsafe { libc::setuid(caller.uid) } != 0
        {
            unsafe { libc::_exit(126) };
        }
        let result = bridge(master);
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }
    unsafe {
        libc::close(master);
        libc::close(1);
    }
    let result = if broker < 0 {
        Err("não foi possível iniciar o encaminhador PTY".into())
    } else {
        supervise(pid, broker, &target)
    };
    if broker > 0 {
        unsafe { libc::kill(broker, libc::SIGKILL) };
    }
    terminate_shell(pid);
    if broker > 0 {
        reap(broker);
    }
    result
}

fn supervise(shell: libc::pid_t, broker: libc::pid_t, target: &Account) -> Result<(), String> {
    let mut next_check = std::time::Instant::now();
    loop {
        if child_exited(shell)? || child_exited(broker)? {
            return Ok(());
        }
        if std::time::Instant::now() >= next_check {
            let name = target.name.to_str().map_err(|_| "identidade inválida")?;
            let current = account(name)?;
            if current.uid != target.uid || current.uid == 0 || !is_wheel_member(&current)? {
                return Err("privilégio do terminal revogado".into());
            }
            next_check = std::time::Instant::now() + std::time::Duration::from_secs(1);
        }
        let mut peer = libc::pollfd {
            fd: 0,
            events: libc::POLLRDHUP,
            revents: 0,
        };
        // Observing hangup does not consume frames. This also cancels a
        // broker blocked writing to a PTY whose shell is no longer reading.
        if unsafe { libc::poll(&mut peer, 1, 100) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("supervisão PTY: {error}"));
        }
        if peer.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(());
        }
    }
}

fn child_exited(pid: libc::pid_t) -> Result<bool, String> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            pid as _,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } < 0
    {
        return Err(format!("waitid: {}", io::Error::last_os_error()));
    }
    // Do not reap before signalling: keeping the child prevents PID reuse.
    Ok(unsafe { info.si_pid() } != 0)
}

fn terminate_shell(pid: libc::pid_t) {
    unsafe {
        libc::kill(-pid, libc::SIGHUP);
        libc::kill(pid, libc::SIGHUP);
    }
    let until = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while std::time::Instant::now() < until && matches!(child_exited(pid), Ok(false)) {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
    reap(pid);
    // KillMode=control-group also cleans up descendants which started a
    // separate process group/session when the supervisor exits.
}

fn reap(pid: libc::pid_t) {
    while unsafe { libc::waitpid(pid, ptr::null_mut(), 0) } < 0 {
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break;
        }
    }
}

fn parse_mode() -> Result<(), String> {
    let mut args = std::env::args();
    let _program = args.next();
    if args.next().as_deref() != Some("--socket") || args.next().is_some() {
        return Err("uso: helper --socket".into());
    }
    Ok(())
}

fn peer_uid(fd: RawFd) -> Result<libc::uid_t, String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(format!(
            "SO_PEERCRED falhou: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(credentials.uid)
}

fn read_username(fd: RawFd) -> io::Result<String> {
    let mut kind = [0_u8; 1];
    if !read_exact(fd, &mut kind)? || kind[0] != b'U' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quadro de usuário ausente",
        ));
    }
    let mut length = [0_u8; 2];
    if !read_exact(fd, &mut length)? {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "usuário incompleto",
        ));
    }
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tamanho de usuário inválido",
        ));
    }
    let mut value = vec![0; length];
    if !read_exact(fd, &mut value)? {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "usuário incompleto",
        ));
    }
    String::from_utf8(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "usuário não é UTF-8"))
}

fn account(name: &str) -> Result<Account, String> {
    let cname = CString::new(name).map_err(|_| "nome de usuário inválido")?;
    let pwd = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pwd.is_null() {
        return Err(format!("conta {name} não encontrada"));
    }
    let pwd = unsafe { &*pwd };
    let copy = |value: *const libc::c_char, fallback: &str| -> CString {
        if value.is_null() {
            CString::new(fallback).unwrap()
        } else {
            unsafe { CStr::from_ptr(value) }.to_owned()
        }
    };
    Ok(Account {
        name: copy(pwd.pw_name, name),
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: copy(pwd.pw_dir, "/"),
        shell: copy(pwd.pw_shell, "/bin/sh"),
    })
}

fn is_wheel_member(user: &Account) -> Result<bool, String> {
    let wheel_name = CString::new("wheel").unwrap();
    let wheel = unsafe { libc::getgrnam(wheel_name.as_ptr()) };
    if wheel.is_null() {
        return Err("grupo wheel não existe".into());
    }
    let wheel_gid = unsafe { (*wheel).gr_gid };
    if user.gid == wheel_gid {
        return Ok(true);
    }

    let mut count: libc::c_int = 0;
    unsafe { libc::getgrouplist(user.name.as_ptr(), user.gid, ptr::null_mut(), &mut count) };
    if count <= 0 {
        return Ok(false);
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    if unsafe {
        libc::getgrouplist(
            user.name.as_ptr(),
            user.gid,
            groups.as_mut_ptr(),
            &mut count,
        )
    } < 0
    {
        return Err("não foi possível resolver os grupos do usuário".into());
    }
    Ok(groups[..count as usize].contains(&wheel_gid))
}

fn child_exec(user: &Account) -> ! {
    unsafe {
        if libc::initgroups(user.name.as_ptr(), user.gid) != 0
            || libc::setgid(user.gid) != 0
            || libc::setuid(user.uid) != 0
        {
            libc::_exit(126);
        }
        libc::umask(0o022);
        libc::chdir(user.home.as_ptr());
        libc::clearenv();
    }
    set_env("HOME", &user.home);
    set_env("USER", &user.name);
    set_env("LOGNAME", &user.name);
    set_env("SHELL", &user.shell);
    set_env("TERM", &CString::new("xterm-256color").unwrap());
    set_env(
        "PATH",
        &CString::new("/usr/local/bin:/usr/bin:/bin").unwrap(),
    );
    let shell_name = unsafe { CStr::from_ptr(user.shell.as_ptr()) }.to_string_lossy();
    let base = shell_name.rsplit('/').next().unwrap_or("sh");
    let argv0 = CString::new(format!("-{base}")).unwrap();
    let argv = [argv0.as_ptr(), ptr::null()];
    unsafe {
        libc::execv(user.shell.as_ptr(), argv.as_ptr());
        libc::_exit(127);
    }
}

fn set_env(key: &str, value: &CStr) {
    let key = CString::new(key).unwrap();
    unsafe {
        libc::setenv(key.as_ptr(), value.as_ptr(), 1);
    }
}

fn bridge(master: RawFd) -> io::Result<()> {
    let mut output = [0_u8; 8192];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(());
        }
        if fds[0].revents & libc::POLLIN != 0 && !read_frame(master)? {
            return Ok(());
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let count = unsafe { libc::read(master, output.as_mut_ptr().cast(), output.len()) };
            if count <= 0 {
                return Ok(());
            }
            write_all(1, &output[..count as usize])?;
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(());
        }
    }
}

fn read_frame(master: RawFd) -> io::Result<bool> {
    let mut kind = [0_u8; 1];
    if !read_exact(0, &mut kind)? {
        return Ok(false);
    }
    match kind[0] {
        b'I' => {
            let mut length = [0_u8; 4];
            if !read_exact(0, &mut length)? {
                return Ok(false);
            }
            let length = u32::from_be_bytes(length) as usize;
            if length > MAX_INPUT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entrada grande demais",
                ));
            }
            let mut data = vec![0; length];
            if !read_exact(0, &mut data)? {
                return Ok(false);
            }
            write_all(master, &data)?;
        }
        b'R' => {
            let mut dimensions = [0_u8; 4];
            if !read_exact(0, &mut dimensions)? {
                return Ok(false);
            }
            let size = libc::winsize {
                ws_col: u16::from_be_bytes([dimensions[0], dimensions[1]]).clamp(20, 500),
                ws_row: u16::from_be_bytes([dimensions[2], dimensions[3]]).clamp(5, 300),
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            if unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &size) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quadro desconhecido",
            ));
        }
    }
    Ok(true)
}

fn read_exact(fd: RawFd, mut data: &mut [u8]) -> io::Result<bool> {
    while !data.is_empty() {
        let count = unsafe { libc::read(fd, data.as_mut_ptr().cast(), data.len()) };
        if count == 0 {
            return Ok(false);
        }
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        data = &mut data[count as usize..];
    }
    Ok(true)
}

fn write_all(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let count = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        data = &data[count as usize..];
    }
    Ok(())
}
