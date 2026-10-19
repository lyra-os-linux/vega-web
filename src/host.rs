//! Identity of the machine the panel runs on, shown on the login page.
//!
//! The login page has no session and must not reach the daemon, so only
//! kernel and release files are read, all world-readable inside the service
//! sandbox: the hostname and kernel release from `/proc/sys/kernel`, the
//! addresses from `/proc/net/fib_trie`, the edition from `/etc/os-release` and the
//! Secure Boot variable from efivars. Everything degrades to an empty value.

use std::net::Ipv4Addr;

pub struct HostIdentity {
    pub hostname: String,
    pub addresses: Vec<String>,
    pub edition: String,
    pub arch: &'static str,
    pub kernel: String,
    pub secure_boot: Option<bool>,
}

pub fn identity() -> HostIdentity {
    HostIdentity {
        hostname: read_trimmed("/proc/sys/kernel/hostname")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "localhost".to_owned()),
        addresses: addresses(),
        edition: os_release_pretty_name().unwrap_or_default(),
        arch: std::env::consts::ARCH,
        kernel: read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_default(),
        secure_boot: secure_boot(),
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn os_release_pretty_name() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim().trim_matches('"').to_owned())
}

/// The UEFI SecureBoot variable: four bytes of attributes, then the flag.
fn secure_boot() -> Option<bool> {
    let data =
        std::fs::read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
            .ok()?;
    data.get(4).map(|flag| *flag == 1)
}

/// IPv4 addresses configured on this host, loopback excluded.
///
/// Read from `/proc/net/fib_trie` instead of `getifaddrs`: the service
/// sandbox restricts address families to AF_UNIX/AF_INET/AF_INET6, so the
/// netlink socket behind `getifaddrs` is refused there. In the trie, a local
/// address is a `|-- a.b.c.d` node followed by a `/32 host LOCAL` leaf.
fn addresses() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string("/proc/net/fib_trie") else {
        return Vec::new();
    };
    let mut list = Vec::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(address) = line.strip_prefix("|-- ") {
            last = address.trim().parse().ok();
        } else if line.starts_with("/32 host LOCAL") {
            list.extend(
                last.take()
                    .filter(|address| !address.is_loopback() && !address.is_unspecified())
                    .map(|address| address.to_string()),
            );
        }
    }
    list.sort_by_key(|value| value.parse::<Ipv4Addr>().ok());
    list.dedup();
    list
}
