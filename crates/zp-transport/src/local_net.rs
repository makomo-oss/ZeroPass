//! Which addresses count as "the local network".
//!
//! ZeroPass never sends sync data to the internet. The LAN transport therefore
//! only listens on, connects to and accepts from addresses that cannot be
//! routed beyond the local link or site.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

/// Whether `ip` is an address that stays on the local network: private
/// (RFC 1918), link-local, or loopback for IPv4; unique-local, link-local or
/// loopback for IPv6. Everything else, including carrier-grade NAT space and
/// every public address, is refused.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback(),
        IpAddr::V6(ip) => {
            // An IPv4-mapped address is judged as the IPv4 address it carries.
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_local(IpAddr::V4(mapped));
            }
            let first = ip.segments()[0];
            // fe80::/10 (link-local) and fc00::/7 (unique local).
            ip.is_loopback() || first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00
        }
    }
}

/// The private and link-local IPv4 addresses of this machine's network
/// interfaces, sorted. Loopback is left out: there is nobody to sync with there.
pub fn local_ipv4_addresses() -> io::Result<Vec<Ipv4Addr>> {
    let mut addresses: Vec<Ipv4Addr> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|interface| match interface.addr.ip() {
            IpAddr::V4(ip) if !ip.is_loopback() && is_local(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
        .collect();
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(text: &str) -> bool {
        is_local(text.parse().unwrap())
    }

    #[test]
    fn private_link_local_and_loopback_addresses_are_local() {
        for address in [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.255.254",
            "169.254.10.20",
            "127.0.0.1",
            "::1",
            "fe80::1",
            "febf::1",
            "fd12:3456:789a::1",
            "fc00::1",
            "::ffff:192.168.1.5",
        ] {
            assert!(local(address), "{address} should be local");
        }
    }

    #[test]
    fn everything_routable_is_refused() {
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.167.255.255",
            "192.169.0.1",
            "11.0.0.1",
            "100.64.0.1", // carrier-grade NAT
            "169.253.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.251", // multicast
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "fec0::1",  // deprecated site-local
            "ff02::fb", // multicast
            "::",
            "::ffff:8.8.8.8",
        ] {
            assert!(!local(address), "{address} must not be treated as local");
        }
    }

    #[test]
    fn this_machines_addresses_are_all_local_and_not_loopback() {
        let addresses = local_ipv4_addresses().unwrap();
        for address in addresses {
            assert!(is_local(IpAddr::V4(address)));
            assert!(!address.is_loopback());
        }
    }
}
