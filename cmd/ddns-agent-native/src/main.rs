mod config;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_https;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "windows")]
use windows as platform;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("certimate-ddns-agent supports Linux and Windows");

use serde::Serialize;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_REPORT_BYTES: usize = 128 << 10;
const MAX_INTERFACES: usize = 128;
const MAX_ADDRESSES: usize = 128;

#[derive(Serialize)]
pub(crate) struct InterfaceReport {
    pub name: String,
    pub mac: String,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

#[derive(Serialize)]
struct Report<'a> {
    hostname: &'a str,
    interfaces: &'a [InterfaceReport],
}

fn usable_ipv4(ip: &Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

fn normalize_interfaces(interfaces: &mut [InterfaceReport]) -> Result<(), &'static str> {
    if interfaces.len() > MAX_INTERFACES {
        return Err("too many network interfaces; narrow the interfaces configuration");
    }
    interfaces.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    if interfaces
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        return Err("multiple network interfaces use the same name");
    }
    for interface in interfaces {
        if !config::valid_text(&interface.name, 128) {
            return Err("invalid network interface name");
        }
        interface.ipv6.retain(|ip| {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                interface.ipv4.push(ipv4);
                return false;
            }
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        });
        interface.ipv4.retain(usable_ipv4);
        interface.ipv4.sort_unstable();
        interface.ipv4.dedup();
        interface.ipv6.sort_unstable();
        interface.ipv6.dedup();
        if interface.ipv4.len() > MAX_ADDRESSES || interface.ipv6.len() > MAX_ADDRESSES {
            return Err("a network interface has too many addresses");
        }
    }
    Ok(())
}

fn run(path: &Path) -> Result<(), String> {
    let config = config::load(path)?;
    let hostname = match config.hostname {
        Some(name) if !name.is_empty() => name,
        _ => platform::hostname()?,
    };
    if !config::valid_text(&hostname, 253) {
        return Err("invalid hostname; specify a valid hostname in the configuration".into());
    }
    let mut interfaces = platform::collect_interfaces(&config.interfaces)?;
    normalize_interfaces(&mut interfaces)?;
    let body = serde_json::to_vec(&Report {
        hostname: &hostname,
        interfaces: &interfaces,
    })
    .map_err(|_| "could not encode the network report")?;
    if body.len() > MAX_REPORT_BYTES {
        return Err("network report exceeds 128 KiB; narrow the interfaces configuration".into());
    }
    platform::send_report(&config.endpoint, &config.token, &body)
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let mut path = PathBuf::from("ddns-agent.json");
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-config" | "--config") => {
                let Some(value) = args.next() else {
                    eprintln!("certimate-ddns-agent: configuration path is required");
                    return ExitCode::FAILURE;
                };
                path = value.into();
            }
            // The native agent always sends one report. Keep the Go agent's flag.
            Some("-once" | "--once") => {}
            Some("-help" | "--help" | "-h") => {
                println!(
                    "Usage: certimate-ddns-agent [--config FILE]\nSend one network report and exit."
                );
                return ExitCode::SUCCESS;
            }
            Some("--version") => {
                println!(
                    "certimate-ddns-agent {} (native)",
                    env!("CARGO_PKG_VERSION")
                );
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("certimate-ddns-agent: unexpected argument; use --help");
                return ExitCode::FAILURE;
            }
        }
    }
    match run(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("certimate-ddns-agent: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_usable_addresses_and_preserves_wire_format() {
        let mut interfaces = [InterfaceReport {
            name: "Ethernet 2".into(),
            mac: "02:12:34:56:78:9a".into(),
            ipv4: vec![Ipv4Addr::LOCALHOST, Ipv4Addr::new(10, 0, 0, 2)],
            ipv6: [
                "2001:db8::2",
                "::ffff:10.0.0.2",
                "2001:db8::1",
                "fd00::3",
                "fe80::4",
                "::1",
            ]
            .map(|address| address.parse().unwrap())
            .to_vec(),
        }];
        normalize_interfaces(&mut interfaces).unwrap();
        let encoded = serde_json::to_string(&Report {
            hostname: "vm-test",
            interfaces: &interfaces,
        })
        .unwrap();
        assert_eq!(
            encoded,
            r#"{"hostname":"vm-test","interfaces":[{"name":"Ethernet 2","mac":"02:12:34:56:78:9a","ipv4":["10.0.0.2"],"ipv6":["2001:db8::1","2001:db8::2","fd00::3"]}]}"#,
        );
    }
}
