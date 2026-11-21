use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

const MAX_CONFIG_BYTES: u64 = 64 << 10;
const REPORT_PATH: &str = "/api/ddns/report";
const INVALID_CONFIG: &str = "configuration must be one JSON object with supported fields";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    server: String,
    token: String,
    interfaces: Option<Vec<String>>,
    hostname: Option<String>,
    // Scheduling belongs to systemd / Task Scheduler. Old files remain valid.
    #[serde(rename = "interval")]
    _interval: Option<String>,
}

pub(crate) struct Config {
    pub endpoint: String,
    pub token: String,
    pub interfaces: Vec<String>,
    pub hostname: Option<String>,
}

pub(crate) fn load(path: &Path) -> Result<Config, String> {
    let file = File::open(path)
        .map_err(|error| format!("could not open agent configuration ({})", error.kind()))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read agent configuration")?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("agent configuration exceeds 64 KiB".into());
    }
    parse(&bytes).map_err(Into::into)
}

fn parse(bytes: &[u8]) -> Result<Config, &'static str> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(INVALID_CONFIG);
    }
    let config: FileConfig = serde_json::from_slice(bytes).map_err(|_| INVALID_CONFIG)?;
    let endpoint =
        endpoint(&config.server).ok_or("server must be an HTTPS origin, with an optional port")?;
    if !valid_token(&config.token) {
        return Err("token must be the node token from Certimate");
    }
    let interfaces = config.interfaces.unwrap_or_default();
    if interfaces.len() > super::MAX_INTERFACES
        || interfaces.iter().any(|name| !valid_text(name, 128))
    {
        return Err("interfaces must contain valid network interface names");
    }
    if let Some(name) = &config.hostname {
        if !name.is_empty() && !valid_text(name, 253) {
            return Err("hostname must be a valid host label");
        }
    }
    Ok(Config {
        endpoint,
        token: config.token,
        interfaces,
        hostname: config.hostname,
    })
}

fn valid_token(value: &str) -> bool {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = value.as_bytes();
    // The server issues exactly 32 bytes encoded as unpadded base64url.
    bytes.len() == 43
        && bytes[..42].iter().all(|byte| ALPHABET.contains(byte))
        && ALPHABET.iter().step_by(4).any(|byte| *byte == bytes[42])
}

pub(crate) fn valid_text(value: &str, bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

// Accept only a DNS name or IP literal with an optional port and root slash.
// Both platform transports receive the same validated authority.
fn endpoint(origin: &str) -> Option<String> {
    let (scheme, authority) = origin.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    let port = if let Some(literal) = authority.strip_prefix('[') {
        let (host, suffix) = literal.split_once(']')?;
        host.parse::<Ipv6Addr>().ok()?;
        if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?)
        }
    } else {
        let (host, port) = if let Some((host, port)) = authority.split_once(':') {
            (host, Some(port))
        } else {
            (authority, None)
        };
        if !valid_host(host) {
            return None;
        }
        port
    };
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok()? == 0
        {
            return None;
        }
    }
    Some(format!("https://{authority}{REPORT_PATH}"))
}

fn valid_host(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    host.len() <= 253
        && !host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_existing_configuration_fields() {
        let config = parse(b"\xef\xbb\xbf{\"server\":\"https://dns.example.test/\",\"token\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"interfaces\":[\"Ethernet 2\"],\"interval\":\"5m\"}").unwrap();
        assert_eq!(config.endpoint, "https://dns.example.test/api/ddns/report");
        assert_eq!(config.interfaces, ["Ethernet 2"]);
        assert!(config.hostname.is_none());
    }

    #[test]
    fn accepts_https_origins_only() {
        for origin in [
            "https://example.test",
            "https://127.0.0.1:8443/",
            "https://[::1]:443",
            "HTTPS://localhost",
        ] {
            assert!(endpoint(origin).unwrap().ends_with(REPORT_PATH));
        }
        for origin in [
            "http://example.test",
            "https://",
            "https://:443",
            "https://example.test/path",
            "https://example.test//",
            "https://example.test?",
            "https://example.test/#",
            "https://user@example.test",
            "https://example.test\\suffix",
            "https://example.test%2F",
            "https://example.test:",
            "https://example.test:65536",
            "https://host:0",
            "https://host:+443",
            "https://[::1]x",
            "https://[fe80::1%eth0]",
            "https://127.1",
            "https://01.0.0.1",
            "https://example.test\n",
        ] {
            assert!(endpoint(origin).is_none(), "accepted {origin:?}");
        }
    }

    #[test]
    fn rejects_credentials_and_unknown_fields_without_echoing_input() {
        for raw in [
            br#"{"server":"https://dns.example.test","token":"test\r\ninjected"}"#.as_slice(),
            br#"{"server":"https://dns.example.test","token":"synthetic-token","provider":"synthetic-secret"}"#,
            br#"{"server":"https://dns.example.test","token":"synthetic-token","token":"duplicate"}"#,
            br#"{"server":"https://dns.example.test","token":"synthetic-token"}{}"#,
            br#"["https://dns.example.test","synthetic-token",[],null,null]"#,
        ] {
            let Err(error) = parse(raw) else { panic!("invalid configuration was accepted"); };
            assert!(!error.contains("synthetic"));
        }
    }
}
