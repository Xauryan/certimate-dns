use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPORT_TIMEOUT: Duration = Duration::from_secs(20);
const RESPONSE_LIMIT: usize = 16 << 10;

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

struct DeadlineSocket {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for DeadlineSocket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn resolve(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let host = host.to_owned();
    std::thread::Builder::new()
        .spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect());
            let _ = sender.send(result);
        })
        .map_err(|_| "could not start HTTPS hostname resolution")?;
    let timeout = remaining(deadline).map_err(|_| "HTTPS hostname resolution timed out")?;
    receiver
        .recv_timeout(timeout)
        .map_err(|_| "HTTPS hostname resolution timed out")?
        .map_err(|_| "could not resolve the HTTPS hostname".into())
}

fn connect(host: &str, port: u16, deadline: Instant) -> Result<TcpStream, String> {
    let addresses = resolve(host, port, deadline)?;
    let multi = addresses.len() > 1;
    for address in addresses {
        let left = remaining(deadline).map_err(|_| "HTTPS connection timed out")?;
        let timeout = if multi {
            left.min(Duration::from_secs(2))
        } else {
            left
        };
        if let Ok(socket) = TcpStream::connect_timeout(&address, timeout) {
            return Ok(socket);
        }
    }
    Err("could not connect to the HTTPS reporting endpoint".into())
}

fn target(url: &str) -> Option<(&str, &str, u16)> {
    let authority = url
        .strip_prefix("https://")?
        .strip_suffix("/api/ddns/report")?;
    let (host, port) = if let Some(literal) = authority.strip_prefix('[') {
        let (host, suffix) = literal.split_once(']')?;
        (host, suffix.strip_prefix(':'))
    } else if let Some((host, port)) = authority.split_once(':') {
        (host, Some(port))
    } else {
        (authority, None)
    };
    let port = match port {
        Some(port) => port.parse().ok()?,
        None => 443,
    };
    Some((authority, host, port))
}

fn status(response: &mut impl Read) -> Result<u16, String> {
    let mut buffer = [0; RESPONSE_LIMIT];
    let mut used = 0;
    while used < buffer.len() {
        let count = response
            .read(&mut buffer[used..])
            .map_err(|_| "could not read HTTPS report response")?;
        if count == 0 {
            break;
        }
        used += count;
        let mut headers = [httparse::EMPTY_HEADER; 48];
        let mut parsed = httparse::Response::new(&mut headers);
        match parsed.parse(&buffer[..used]) {
            Ok(httparse::Status::Complete(_)) => {
                return parsed
                    .code
                    .ok_or_else(|| "invalid HTTPS reporting response".into());
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Err("invalid HTTPS reporting response".into()),
        }
    }
    Err("missing or oversized HTTPS reporting response".into())
}

pub fn send_report(url: &str, token: &str, body: &[u8]) -> Result<(), String> {
    let started = Instant::now();
    // Shared configuration validates the hostname, port and node token before this call.
    let (authority, host, port) = target(url).ok_or("invalid HTTPS reporting endpoint")?;
    let server_name = ServerName::try_from(host.trim_end_matches('.').to_owned())
        .map_err(|_| "invalid TLS server identity")?;

    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        return Err("could not load Linux certificate trust anchors".into());
    }
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| "could not configure TLS versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let mut session = ClientConnection::new(Arc::new(tls), server_name)
        .map_err(|_| "could not initialize HTTPS session")?;

    let deadline = started + CONNECT_TIMEOUT;
    let mut socket = DeadlineSocket {
        stream: connect(host, port, deadline)?,
        deadline,
    };
    socket
        .stream
        .set_nodelay(true)
        .map_err(|_| "could not configure HTTPS connection")?;
    session
        .complete_io(&mut socket)
        .map_err(|_| "HTTPS TLS verification or negotiation failed")?;
    socket.deadline = started + REPORT_TIMEOUT;
    let mut session = StreamOwned::new(session, socket);
    let mut request = format!(
        "POST /api/ddns/report HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ).into_bytes();
    request.extend_from_slice(body);
    session
        .write_all(&request)
        .and_then(|()| session.flush())
        .map_err(|_| "could not send HTTPS report")?;

    let code = status(&mut session)?;
    if code != 204 {
        return Err(format!("DDNS reporting endpoint returned HTTP {code}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_dns_and_bracketed_ipv6_endpoints() {
        assert_eq!(
            target("https://dns.example.test/api/ddns/report"),
            Some(("dns.example.test", "dns.example.test", 443))
        );
        assert_eq!(
            target("https://[2001:db8::4]:8443/api/ddns/report"),
            Some(("[2001:db8::4]:8443", "2001:db8::4", 8443))
        );
        assert!(target("http://dns.example.test/api/ddns/report").is_none());
    }

    #[test]
    fn reads_complete_response_status_without_following_redirects() {
        let mut stream =
            &b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://example.test\r\n\r\n"[..];
        assert_eq!(status(&mut stream).unwrap(), 307);
        let mut partial = &b"HTTP/1.1 204 No Content\r\n"[..];
        assert!(status(&mut partial).is_err());
        assert!(status(&mut io::repeat(b'X').take(RESPONSE_LIMIT as u64)).is_err());
    }
}
