use std::ffi::{CStr, c_void};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr::{null, null_mut};
use std::slice;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, GetLastError};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinHttp::{
    ICU_REJECT_USERPWD, URL_COMPONENTS, WINHTTP_ACCESS_TYPE_NO_PROXY,
    WINHTTP_DISABLE_AUTHENTICATION, WINHTTP_DISABLE_COOKIES, WINHTTP_DISABLE_REDIRECTS,
    WINHTTP_FLAG_SECURE, WINHTTP_INTERNET_SCHEME_HTTPS, WINHTTP_OPTION_CONNECT_RETRIES,
    WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpCrackUrl, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetOption, WinHttpSetTimeouts,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated as DAD_DEPRECATED,
    IpDadStatePreferred as DAD_PREFERRED, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows_sys::Win32::System::SystemInformation::{
    ComputerNamePhysicalDnsHostname, GetComputerNameExW,
};
use windows_sys::w;

use crate::InterfaceReport;

fn last_error(operation: &str) -> String {
    format!("{operation} failed (Windows error {})", unsafe {
        GetLastError()
    })
}

pub fn hostname() -> Result<String, String> {
    let mut name = [0u16; 256];
    let mut length = name.len() as u32;
    if unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            name.as_mut_ptr(),
            &mut length,
        )
    } == 0
    {
        return Err(last_error("read hostname"));
    }
    String::from_utf16(&name[..length as usize]).map_err(|_| "invalid Windows hostname".into())
}

unsafe fn adapter_name(adapter: &IP_ADAPTER_ADDRESSES_LH) -> String {
    // The API returns adapter strings terminated by NUL within its output buffer.
    let friendly = adapter.FriendlyName;
    if !friendly.is_null() {
        let mut length = 0;
        while unsafe { *friendly.add(length) } != 0 {
            length += 1;
        }
        if length > 0 {
            return String::from_utf16_lossy(unsafe { slice::from_raw_parts(friendly, length) });
        }
    }
    if adapter.AdapterName.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(adapter.AdapterName.cast()) }
        .to_string_lossy()
        .into_owned()
}

pub fn collect_interfaces(selected: &[String]) -> Result<Vec<InterfaceReport>, String> {
    let mut flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if !selected.is_empty() {
        // Look up explicitly selected interfaces even when they do not have an IP binding.
        flags |= GAA_FLAG_INCLUDE_ALL_INTERFACES;
    }
    let mut bytes = 16 * 1024u32;
    // The required size can change between calls when an interface changes state.
    for _ in 0..3 {
        if bytes > 4 * 1024 * 1024 {
            return Err("Windows adapter snapshot exceeds size limit".into());
        }
        let mut storage = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::new();
        storage.resize_with(
            (bytes as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>()),
            MaybeUninit::zeroed,
        );
        let first = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status =
            unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, null(), first, &mut bytes) };
        match status {
            0 => return Ok(unsafe { read_adapters(first, selected) }),
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW => continue,
            _ => {
                return Err(format!(
                    "list network interfaces failed (Windows error {status})"
                ));
            }
        }
    }
    Err("Windows adapter snapshot kept changing".into())
}

// The linked lists and all string and address pointers remain valid while the
// buffer filled by GetAdaptersAddresses is alive.
unsafe fn read_adapters(
    mut next: *mut IP_ADAPTER_ADDRESSES_LH,
    selected: &[String],
) -> Vec<InterfaceReport> {
    let mut result = Vec::new();
    while let Some(adapter) = unsafe { next.as_ref() } {
        next = adapter.Next;
        let up = adapter.OperStatus == IfOperStatusUp;
        if adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK || (!up && selected.is_empty()) {
            continue;
        }
        let name = unsafe { adapter_name(adapter) };
        if name.is_empty() || (!selected.is_empty() && !selected.contains(&name)) {
            continue;
        }
        let physical = adapter
            .PhysicalAddress
            .get(..adapter.PhysicalAddressLength as usize);
        let mac = match physical {
            Some(bytes) if matches!(bytes.len(), 6 | 8) => bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
            _ => String::new(),
        };
        let mut report = InterfaceReport {
            name,
            mac,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        };
        if up {
            let mut cursor = adapter.FirstUnicastAddress;
            while let Some(address) = unsafe { cursor.as_ref() } {
                cursor = address.Next;
                // Keep every valid address, including still-valid deprecated IPv6
                // addresses, so server-side selection can retain a published address.
                if !matches!(address.DadState, DAD_PREFERRED | DAD_DEPRECATED) {
                    continue;
                }
                let socket = address.Address.lpSockaddr;
                let length = address.Address.iSockaddrLength;
                if socket.is_null() || length < size_of::<u16>() as i32 {
                    continue;
                }
                match unsafe { (*socket).sa_family } {
                    AF_INET if length >= size_of::<SOCKADDR_IN>() as i32 => {
                        let ip = unsafe { (*socket.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr };
                        report.ipv4.push(Ipv4Addr::from(ip.to_ne_bytes()));
                    }
                    AF_INET6 if length >= size_of::<SOCKADDR_IN6>() as i32 => {
                        let ip = unsafe { (*socket.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte };
                        report.ipv6.push(Ipv6Addr::from(ip));
                    }
                    _ => {}
                }
            }
        }
        result.push(report);
    }
    result
}

struct HttpHandle(*mut c_void);

impl HttpHandle {
    fn new(handle: *mut c_void, operation: &str) -> Result<Self, String> {
        if handle.is_null() {
            Err(last_error(operation))
        } else {
            Ok(Self(handle))
        }
    }

    fn set_option(&self, option: u32, value: u32, operation: &str) -> Result<(), String> {
        let value_ptr = (&raw const value).cast();
        if unsafe { WinHttpSetOption(self.0, option, value_ptr, size_of::<u32>() as u32) } == 0 {
            return Err(last_error(operation));
        }
        Ok(())
    }
}

impl Drop for HttpHandle {
    fn drop(&mut self) {
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn https_parts(url: &str) -> Result<(Vec<u16>, u16, Vec<u16>), String> {
    if !url.starts_with("https://") || url.contains(['\0', '?', '#', '\\']) {
        return Err("invalid HTTPS report URL".into());
    }
    let mut parts = URL_COMPONENTS {
        dwStructSize: size_of::<URL_COMPONENTS>() as u32,
        dwHostNameLength: 1,
        dwUrlPathLength: 1,
        ..URL_COMPONENTS::default()
    };
    let input = wide(url);
    if unsafe { WinHttpCrackUrl(input.as_ptr(), 0, ICU_REJECT_USERPWD, &mut parts) } == 0 {
        return Err(last_error("parse HTTPS report URL"));
    }
    if parts.nScheme != WINHTTP_INTERNET_SCHEME_HTTPS
        || parts.dwHostNameLength == 0
        || parts.dwUrlPathLength == 0
    {
        return Err("invalid HTTPS report URL".into());
    }
    // WinHttpCrackUrl returns pointers to the substrings of input. Connect
    // and OpenRequest take independent NUL-terminated strings.
    let host =
        unsafe { slice::from_raw_parts(parts.lpszHostName, parts.dwHostNameLength as usize) };
    let path = unsafe { slice::from_raw_parts(parts.lpszUrlPath, parts.dwUrlPathLength as usize) };
    let terminated = |part: &[u16]| part.iter().copied().chain(std::iter::once(0)).collect();
    Ok((terminated(host), parts.nPort, terminated(path)))
}

pub fn send_report(url: &str, token: &str, body: &[u8]) -> Result<(), String> {
    let (host, port, path) = https_parts(url)?;
    let body_len = u32::try_from(body.len()).map_err(|_| "report is too large")?;
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid node token".into());
    }
    let headers = wide(&format!(
        "Content-Type: application/json\r\nAuthorization: Bearer {token}\r\n"
    ));
    let session = HttpHandle::new(
        // Direct WinHTTP session, independent of a signed-in desktop user's proxy settings.
        unsafe {
            WinHttpOpen(
                w!("certimate-ddns-agent"),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                null(),
                null(),
                0,
            )
        },
        "start WinHTTP",
    )?;
    if unsafe { WinHttpSetTimeouts(session.0, 3_000, 4_000, 3_000, 4_000) } == 0 {
        return Err(last_error("set report timeouts"));
    }
    session.set_option(WINHTTP_OPTION_CONNECT_RETRIES, 2, "set connection attempts")?;
    session.set_option(
        WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT,
        7_000,
        "set response deadline",
    )?;
    let connection = HttpHandle::new(
        unsafe { WinHttpConnect(session.0, host.as_ptr(), port, 0) },
        "open HTTPS connection",
    )?;
    let request = HttpHandle::new(
        // WINHTTP_FLAG_SECURE uses normal Schannel certificate and host verification.
        unsafe {
            WinHttpOpenRequest(
                connection.0,
                w!("POST"),
                path.as_ptr(),
                null(),
                null(),
                null(),
                WINHTTP_FLAG_SECURE,
            )
        },
        "open HTTPS report request",
    )?;
    request.set_option(
        WINHTTP_OPTION_DISABLE_FEATURE,
        WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES,
        "set HTTPS report request policy",
    )?;
    if unsafe {
        WinHttpSendRequest(
            request.0,
            headers.as_ptr(),
            (headers.len() - 1) as u32,
            body.as_ptr().cast(),
            body_len,
            body_len,
            0,
        )
    } == 0
    {
        return Err(last_error("send HTTPS report"));
    }
    if unsafe { WinHttpReceiveResponse(request.0, null_mut()) } == 0 {
        return Err(last_error("receive HTTPS report response"));
    }
    let mut status = 0u32;
    let mut status_size = size_of::<u32>() as u32;
    if unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&raw mut status).cast(),
            &mut status_size,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error("read HTTPS report status"));
    }
    if status != 204 {
        return Err(format!("report rejected (HTTP {status})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH;
    use windows_sys::Win32::Networking::WinSock::IpDadStateTentative;

    #[test]
    fn reads_friendly_name_and_multiple_ipv6_addresses() {
        let mut name = wide("以太网");
        let mut sockets: [SOCKADDR_IN6; 3] = std::array::from_fn(|index| {
            let mut socket = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };
            socket.sin6_addr.u.Byte =
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, index as u16 + 1).octets();
            socket
        });
        let mut unicast: [IP_ADAPTER_UNICAST_ADDRESS_LH; 3] = std::array::from_fn(|index| {
            let mut address = IP_ADAPTER_UNICAST_ADDRESS_LH {
                DadState: [DAD_PREFERRED, DAD_DEPRECATED, IpDadStateTentative][index],
                ..Default::default()
            };
            address.Address.lpSockaddr = (&raw mut sockets[index]).cast();
            address.Address.iSockaddrLength = size_of::<SOCKADDR_IN6>() as i32;
            address
        });
        unicast[0].Next = &raw mut unicast[1];
        unicast[1].Next = &raw mut unicast[2];
        let mut adapter = IP_ADAPTER_ADDRESSES_LH {
            FriendlyName: name.as_mut_ptr(),
            OperStatus: IfOperStatusUp,
            PhysicalAddress: [2, 0, 0, 0, 0, 1, 0, 0],
            PhysicalAddressLength: 6,
            FirstUnicastAddress: unicast.as_mut_ptr(),
            ..Default::default()
        };
        let reported = unsafe { read_adapters(&raw mut adapter, &["以太网".into()]) };
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].name, "以太网");
        assert_eq!(reported[0].mac, "02:00:00:00:00:01");
        assert_eq!(
            reported[0].ipv6,
            [
                "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                "2001:db8::2".parse().unwrap()
            ]
        );
    }

    #[test]
    fn accepts_https_and_rejects_cleartext_or_credentials() {
        let (host, port, path) = https_parts("https://example.test:8443/api/ddns/report").unwrap();
        assert_eq!(host, wide("example.test"));
        assert_eq!(port, 8443);
        assert_eq!(path, wide("/api/ddns/report"));
        assert!(https_parts("http://example.test/api/ddns/report").is_err());
        assert!(https_parts("https://user:password@example.test/api/ddns/report").is_err());
    }
}
