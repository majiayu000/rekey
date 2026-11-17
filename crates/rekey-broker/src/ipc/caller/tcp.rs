//! Loopback HTTP peers: map the accepted TCP 4-tuple to the same-UID process
//! that holds the client socket, then label it like a Unix peer (§4.3).
//! Any failure, including another user's client, is `unknown`.
use std::net::SocketAddr;
#[cfg(any(target_os = "linux", test))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `peer` is the client address seen by accept; `local` is the service
/// address. The client's socket has them as its local and foreign ends.
pub(crate) async fn tcp_caller(peer: SocketAddr, local: SocketAddr) -> String {
    tokio::task::spawn_blocking(move || match platform::peer_pid(peer, local) {
        Some(pid) => super::process_caller(pid, |_| cfg!(target_os = "linux")),
        None => "unknown".into(),
    })
    .await
    .unwrap_or_else(|_| "unknown".into())
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::c_int;
    use std::mem::{MaybeUninit, size_of};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::ptr;

    const PROC_UID_ONLY: u32 = 4;
    const PROC_PIDFDSOCKETINFO: c_int = 3;
    const SOCKINFO_TCP: i32 = 2;
    const INI_IPV4: u8 = 1;
    const INI_IPV6: u8 = 2;
    const MAX_ENTRIES: usize = 1 << 16;

    /// `struct socket_fdinfo` from <sys/proc_info.h>, reduced to the TCP
    /// endpoint fields; the size and offsets are fixed by the public ABI.
    #[repr(C, align(8))]
    struct SocketFdInfo {
        _file_and_stat: [u8; 176],
        _type_protocol: [i32; 2],
        soi_family: i32,
        _options_to_buffers: [u8; 68],
        soi_kind: i32,
        _reserved: u32,
        insi_fport: i32,
        insi_lport: i32,
        _generation_flags_flow: [u8; 16],
        insi_vflag: u8,
        _ttl_reserved: [u8; 7],
        insi_faddr: [u8; 16],
        insi_laddr: [u8; 16],
        _rest: [u8; 464],
    }
    const _: () = assert!(size_of::<SocketFdInfo>() == 792);
    const _: () = assert!(std::mem::offset_of!(SocketFdInfo, soi_family) == 184);
    const _: () = assert!(std::mem::offset_of!(SocketFdInfo, soi_kind) == 256);
    const _: () = assert!(std::mem::offset_of!(SocketFdInfo, insi_fport) == 264);
    const _: () = assert!(std::mem::offset_of!(SocketFdInfo, insi_vflag) == 288);
    const _: () = assert!(std::mem::offset_of!(SocketFdInfo, insi_laddr) == 312);

    pub(super) fn peer_pid(peer: SocketAddr, local: SocketAddr) -> Option<i32> {
        let uid = unsafe { libc::geteuid() };
        let pids: Vec<i32> = list(|buffer, bytes| unsafe {
            libc::proc_listpids(PROC_UID_ONLY, uid, buffer, bytes)
        })?;
        pids.into_iter()
            .filter(|pid| *pid > 0)
            .find(|pid| holds(*pid, peer, local))
    }

    fn holds(pid: i32, peer: SocketAddr, local: SocketAddr) -> bool {
        let Some(fds) = list::<libc::proc_fdinfo>(|buffer, bytes| unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buffer, bytes)
        }) else {
            return false;
        };
        fds.iter()
            .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
            .any(|fd| {
                let mut info = MaybeUninit::<SocketFdInfo>::zeroed();
                let size = size_of::<SocketFdInfo>() as c_int;
                let filled = unsafe {
                    libc::proc_pidfdinfo(
                        pid,
                        fd.proc_fd,
                        PROC_PIDFDSOCKETINFO,
                        info.as_mut_ptr().cast(),
                        size,
                    )
                };
                if filled != size {
                    return false;
                }
                // SAFETY: zero-initialized plain data, filled by the kernel.
                let info = unsafe { info.assume_init() };
                info.soi_kind == SOCKINFO_TCP
                    && matches!(info.soi_family, libc::AF_INET | libc::AF_INET6)
                    && endpoint(info.insi_vflag, info.insi_laddr, info.insi_lport) == Some(peer)
                    && endpoint(info.insi_vflag, info.insi_faddr, info.insi_fport) == Some(local)
            })
    }

    /// Kernel ports are network-order `u_short` values widened to `int`.
    fn endpoint(vflag: u8, address: [u8; 16], port: i32) -> Option<SocketAddr> {
        let ip = if vflag & INI_IPV4 != 0 {
            IpAddr::V4(Ipv4Addr::new(
                address[12],
                address[13],
                address[14],
                address[15],
            ))
        } else if vflag & INI_IPV6 != 0 {
            let address = Ipv6Addr::from(address);
            address
                .to_ipv4_mapped()
                .map_or(IpAddr::V6(address), IpAddr::V4)
        } else {
            return None;
        };
        Some(SocketAddr::new(ip, u16::from_be(port as u16)))
    }

    /// Size query, then a bounded fill; entries beyond the kernel's byte
    /// count are discarded.
    fn list<T: Copy>(fill: impl Fn(*mut std::ffi::c_void, c_int) -> c_int) -> Option<Vec<T>> {
        let estimate = fill(ptr::null_mut(), 0);
        if estimate <= 0 {
            return None;
        }
        let capacity = (estimate as usize / size_of::<T>() + 32).min(MAX_ENTRIES);
        let mut entries = Vec::<T>::with_capacity(capacity);
        let bytes = fill(
            entries.as_mut_ptr().cast(),
            (capacity * size_of::<T>()) as c_int,
        );
        if bytes <= 0 {
            return None;
        }
        // SAFETY: the kernel initialized `bytes` bytes of whole entries.
        unsafe { entries.set_len((bytes as usize / size_of::<T>()).min(capacity)) };
        Some(entries)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::net::SocketAddr;

    pub(super) fn peer_pid(peer: SocketAddr, local: SocketAddr) -> Option<i32> {
        let inode = ["/proc/net/tcp", "/proc/net/tcp6"]
            .into_iter()
            .find_map(|table| {
                super::socket_inode(&std::fs::read_to_string(table).ok()?, peer, local)
            })?;
        let link = format!("socket:[{inode}]");
        // Another user's /proc/<pid>/fd is unreadable and simply skipped.
        std::fs::read_dir("/proc")
            .ok()?
            .flatten()
            .find_map(|process| {
                let pid = process.file_name().to_str()?.parse::<i32>().ok()?;
                std::fs::read_dir(process.path().join("fd"))
                    .ok()?
                    .flatten()
                    .any(|fd| {
                        std::fs::read_link(fd.path())
                            .is_ok_and(|target| target.as_os_str() == link.as_str())
                    })
                    .then_some(pid)
            })
    }
}

/// The inode of the socket whose local end is `peer` and foreign end is
/// `local`, from `/proc/net/tcp` or `/proc/net/tcp6` text.
#[cfg(any(target_os = "linux", test))]
fn socket_inode(table: &str, peer: SocketAddr, local: SocketAddr) -> Option<u64> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let inode = fields.get(9)?.parse::<u64>().ok()?;
        (inode != 0
            && proc_address(fields.get(1)?)? == peer
            && proc_address(fields.get(2)?)? == local)
            .then_some(inode)
    })
}

/// `/proc/net/tcp*` print each 32-bit word of the network-order address in
/// host order and the port in host order; IPv4-mapped IPv6 compares as IPv4.
#[cfg(any(target_os = "linux", test))]
fn proc_address(field: &str) -> Option<SocketAddr> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let mut bytes = Vec::with_capacity(16);
    for word in address.as_bytes().chunks(8) {
        let word = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    let ip = match <[u8; 4]>::try_from(bytes.as_slice()) {
        Ok(v4) if address.len() == 8 => IpAddr::V4(Ipv4Addr::from(v4)),
        _ => {
            let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(bytes.as_slice()).ok()?);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_client_socket_resolves_to_the_connecting_process() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(local).unwrap();
        let (_server, peer) = listener.accept().unwrap();
        assert_eq!(
            platform::peer_pid(peer, local),
            Some(std::process::id() as i32)
        );
        // Port 1 is never an ephemeral client port.
        let absent = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        assert_eq!(platform::peer_pid(absent, local), None);
    }

    #[tokio::test]
    async fn tcp_label_is_the_process_label_of_the_client() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(local).unwrap();
        let (_server, peer) = listener.accept().unwrap();
        let label = tcp_caller(peer, local).await;
        assert_ne!(label, "unknown");
        let own = std::process::id() as i32;
        assert_eq!(
            label,
            super::super::process_caller(own, |_| cfg!(target_os = "linux"))
        );
        let absent = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        assert_eq!(tcp_caller(absent, local).await, "unknown");
    }

    // Captured from Linux /proc/net/tcp and /proc/net/tcp6 (little-endian).
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1E6B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41021 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1E6B 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 41587 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:D431 0100007F:1E6B 01 00000000:00000000 00:00000000 00000000  1000        0 41586 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:D432 0100007F:1E6B 06 00000000:00000000 03:00000F4D 00000000     0        0 0 3 0000000000000000
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000100007F:D433 0000000000000000FFFF00000100007F:1E6B 01 00000000:00000000 00:00000000 00000000  1000        0 51200 1 0000000000000000 20 4 30 10 -1
   1: 00000000000000000000000001000000:9C40 00000000000000000000000001000000:1E6B 01 00000000:00000000 00:00000000 00000000  1000        0 51201 1 0000000000000000 20 4 30 10 -1
";

    #[test]
    #[cfg(target_endian = "little")]
    fn proc_net_tcp_rows_map_the_client_end_to_its_inode() {
        let service = SocketAddr::from((Ipv4Addr::LOCALHOST, 7787));
        let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 0xD431));
        // The server's accepted row has the reverse tuple and never matches.
        assert_eq!(socket_inode(TCP, client, service), Some(41586));
        assert_eq!(socket_inode(TCP, service, client), Some(41587));
        // TIME_WAIT rows carry inode 0 and have no owning process.
        let closed = SocketAddr::from((Ipv4Addr::LOCALHOST, 0xD432));
        assert_eq!(socket_inode(TCP, closed, service), None);
        let mapped = SocketAddr::from((Ipv4Addr::LOCALHOST, 0xD433));
        assert_eq!(socket_inode(TCP6, mapped, service), Some(51200));
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 0x9C40));
        let v6_service = SocketAddr::from((Ipv6Addr::LOCALHOST, 7787));
        assert_eq!(socket_inode(TCP6, v6, v6_service), Some(51201));
        assert_eq!(socket_inode("header only\n", client, service), None);
        assert_eq!(proc_address("0100007F"), None);
        assert_eq!(proc_address("XYZ:1E6B"), None);
    }
}
