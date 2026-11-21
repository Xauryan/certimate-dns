use std::collections::BTreeMap;
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::InterfaceReport;
pub use crate::linux_https::send_report;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const AF_PACKET: u16 = 17;
const IFF_UP: c_uint = 0x1;
const IFF_LOOPBACK: c_uint = 0x8;

#[repr(C)]
struct IfAddrs {
    next: *mut IfAddrs,
    name: *const c_char,
    flags: c_uint,
    address: *const SockAddr,
    netmask: *const SockAddr,
    broad_or_dst_addr: *const SockAddr,
    data: *mut c_void,
}

#[repr(C)]
struct SockAddr {
    family: u16,
}

#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16,
    address: [u8; 4],
    padding: [u8; 8],
}

#[repr(C)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flow_info: u32,
    address: [u8; 16],
    scope_id: u32,
}

#[repr(C)]
struct SockAddrLl {
    family: u16,
    protocol: u16,
    interface_index: c_int,
    hardware_type: u16,
    packet_type: u8,
    address_length: u8,
    address: [u8; 8],
}

unsafe extern "C" {
    fn gethostname(name: *mut c_char, size: usize) -> c_int;
    fn getifaddrs(list: *mut *mut IfAddrs) -> c_int;
    fn freeifaddrs(list: *mut IfAddrs);
}

struct IfAddrList(*mut IfAddrs);

impl Drop for IfAddrList {
    fn drop(&mut self) {
        // getifaddrs owns memory for the list, names and socket addresses.
        unsafe { freeifaddrs(self.0) }
    }
}

pub fn hostname() -> Result<String, String> {
    // Linux limits a hostname to 64 bytes, with room for a terminator.
    let mut name = [0_u8; 65];
    if unsafe { gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
        return Err("could not read the Linux hostname".into());
    }
    CStr::from_bytes_until_nul(&name)
        .ok()
        .and_then(|name| name.to_str().ok())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "Linux hostname is empty or invalid UTF-8".into())
}

pub fn collect_interfaces(selected: &[String]) -> Result<Vec<InterfaceReport>, String> {
    let mut first = ptr::null_mut();
    if unsafe { getifaddrs(&mut first) } != 0 {
        return Err("could not enumerate Linux network interfaces".into());
    }
    let list = IfAddrList(first);
    let mut next = list.0;
    let mut interfaces = BTreeMap::new();
    // Each entry and its non-null pointers are valid until list is dropped.
    while let Some(item) = unsafe { next.as_ref() } {
        next = item.next;
        if item.name.is_null() || item.flags & IFF_LOOPBACK != 0 {
            continue;
        }
        let Ok(name) = unsafe { CStr::from_ptr(item.name) }.to_str() else {
            continue;
        };
        let up = item.flags & IFF_UP != 0;
        if (selected.is_empty() && !up)
            || (!selected.is_empty() && !selected.iter().any(|s| s == name))
        {
            continue;
        }
        let report = interfaces.entry(name).or_insert_with(|| InterfaceReport {
            name: name.to_owned(),
            mac: String::new(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        });
        let Some(address) = (unsafe { item.address.as_ref() }) else {
            continue;
        };
        // The kernel-provided address family selects the concrete socket layout.
        match address.family {
            AF_PACKET => {
                let address = unsafe { &*item.address.cast::<SockAddrLl>() };
                let len = usize::from(address.address_length);
                if matches!(len, 6 | 8) {
                    report.mac.clear();
                    for (index, byte) in address.address[..len].iter().enumerate() {
                        if index != 0 {
                            report.mac.push(':');
                        }
                        let _ = write!(&mut report.mac, "{byte:02x}");
                    }
                }
            }
            AF_INET if up => {
                let address = unsafe { &*item.address.cast::<SockAddrIn>() };
                report.ipv4.push(Ipv4Addr::from(address.address));
            }
            AF_INET6 if up => {
                let address = unsafe { &*item.address.cast::<SockAddrIn6>() };
                report.ipv6.push(Ipv6Addr::from(address.address));
            }
            _ => {}
        }
    }
    Ok(interfaces.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_linux_hostname_and_filters_interfaces() {
        assert!(!hostname().unwrap().is_empty());
        assert!(
            collect_interfaces(&["certimate-test-interface-absent".into()])
                .unwrap()
                .is_empty()
        );
        let all = collect_interfaces(&[]).unwrap();
        assert!(!all.iter().any(|report| report.name == "lo"));
        if let Some(first) = all.first() {
            let filtered = collect_interfaces(std::slice::from_ref(&first.name)).unwrap();
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].name, first.name);
            assert_eq!(filtered[0].mac, first.mac);
        }
    }
}
