//! Server specifications: how a resolver endpoint is addressed and named.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Udp => "Do53",
            Proto::Tcp => "Do53-TCP",
            Proto::Tls => "DoT",
            Proto::Https => "DoH",
        }
    }

    pub fn parse(s: &str) -> Result<Proto> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "udp" | "do53" | "plain" | "dns" => Proto::Udp,
            "tcp" => Proto::Tcp,
            "tls" | "dot" => Proto::Tls,
            "https" | "doh" | "http" => Proto::Https,
            other => bail!("unknown protocol '{other}' (use udp, tcp, dot or doh)"),
        })
    }

    fn default_port(self) -> u16 {
        match self {
            Proto::Udp | Proto::Tcp => 53,
            Proto::Tls => 853,
            Proto::Https => 443,
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    /// Human label, e.g. "Cloudflare DNS".
    pub name: String,
    pub proto: Proto,
    /// `host:port` for udp/tcp/tls. Empty for https (see `url`).
    pub target: String,
    /// TLS SNI / certificate name, for DoT.
    pub tls_name: Option<String>,
    /// Full endpoint URL, for DoH.
    pub url: Option<String>,
}

impl Server {
    /// The canonical spec string, i.e. what you'd pass back on the command line.
    pub fn endpoint(&self) -> String {
        match self.proto {
            Proto::Udp => format!("udp://{}", self.target),
            Proto::Tcp => format!("tcp://{}", self.target),
            Proto::Tls => match &self.tls_name {
                Some(n) if !self.target.starts_with(n.as_str()) => {
                    format!("tls://{}#{n}", self.target)
                }
                _ => format!("tls://{}", self.target),
            },
            Proto::Https => self.url.clone().unwrap_or_default(),
        }
    }

    /// Parse one spec, optionally prefixed with a display name: `Name = spec`.
    ///
    /// Accepted specs:
    ///   `1.1.1.1`, `1.1.1.1:5353`, `udp://1.1.1.1`, `tcp://9.9.9.9`,
    ///   `tls://dns.google`, `tls://8.8.8.8#dns.google`, `https://dns.google/dns-query`
    pub fn parse(spec: &str) -> Result<Server> {
        let spec = spec.trim();
        let (name, rest) = split_label(spec);
        let mut server =
            parse_endpoint(rest).with_context(|| format!("bad server spec '{rest}'"))?;
        if let Some(name) = name {
            server.name = name.to_string();
        }
        Ok(server)
    }
}

/// Splits `Name = spec`, being careful not to trip on '=' inside a URL.
fn split_label(spec: &str) -> (Option<&str>, &str) {
    match spec.split_once('=') {
        Some((label, rest)) if !label.contains("://") && !label.contains('/') => {
            (Some(label.trim()), rest.trim())
        }
        _ => (None, spec),
    }
}

fn parse_endpoint(spec: &str) -> Result<Server> {
    if spec.is_empty() {
        bail!("empty spec");
    }
    let (proto, rest) = match spec.split_once("://") {
        Some((scheme, rest)) => (Proto::parse(scheme)?, rest),
        None => (Proto::Udp, spec),
    };

    if proto == Proto::Https {
        let url = if spec.contains("://") {
            spec.to_string()
        } else {
            format!("https://{spec}")
        };
        let host = rest.split(['/', '?']).next().unwrap_or(rest);
        if host.is_empty() {
            bail!("missing host in URL");
        }
        return Ok(Server {
            name: host.to_string(),
            proto,
            target: String::new(),
            tls_name: None,
            url: Some(url),
        });
    }

    // Optional `#tls-name` suffix pins the certificate name when connecting by IP.
    let (hostport, pinned) = match rest.split_once('#') {
        Some((h, n)) => (h.trim(), Some(n.trim().to_string())),
        None => (rest.trim(), None),
    };
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() {
        bail!("missing host");
    }
    let port = port.unwrap_or_else(|| proto.default_port());

    let tls_name = if proto == Proto::Tls {
        match pinned {
            Some(n) => Some(n),
            None if host.parse::<std::net::IpAddr>().is_ok() => {
                bail!("DoT via a bare IP needs a certificate name: tls://{host}#dns.example.com")
            }
            None => Some(host.to_string()),
        }
    } else {
        None
    };

    let target = if host.contains(':') {
        format!("[{host}]:{port}") // IPv6 literal
    } else {
        format!("{host}:{port}")
    };

    Ok(Server {
        name: hostport.to_string(),
        proto,
        target,
        tls_name,
        url: None,
    })
}

/// Splits `host`, `host:port`, `[v6]`, or `[v6]:port`.
fn split_host_port(s: &str) -> Result<(&str, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("unterminated IPv6 literal (missing ']')")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().context("bad port")?),
            None => None,
        };
        return Ok((host, port));
    }
    match s.rsplit_once(':') {
        // A bare IPv6 address has several colons; treat it as a host, not host:port.
        Some((host, port)) if !host.contains(':') => {
            Ok((host, Some(port.parse().context("bad port")?)))
        }
        _ => Ok((s, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ip_defaults_to_udp_53() {
        let s = Server::parse("1.1.1.1").unwrap();
        assert_eq!(s.proto, Proto::Udp);
        assert_eq!(s.target, "1.1.1.1:53");
    }

    #[test]
    fn named_specs_and_ports() {
        let s = Server::parse("Local = udp://127.0.0.1:5353").unwrap();
        assert_eq!(s.name, "Local");
        assert_eq!(s.target, "127.0.0.1:5353");
    }

    #[test]
    fn dot_takes_hostname_as_sni() {
        let s = Server::parse("tls://dns.google").unwrap();
        assert_eq!(s.target, "dns.google:853");
        assert_eq!(s.tls_name.as_deref(), Some("dns.google"));
        assert_eq!(s.endpoint(), "tls://dns.google:853");
    }

    #[test]
    fn dot_by_ip_requires_pinned_name() {
        assert!(Server::parse("tls://8.8.8.8").is_err());
        let s = Server::parse("tls://8.8.8.8#dns.google").unwrap();
        assert_eq!(s.target, "8.8.8.8:853");
        assert_eq!(s.tls_name.as_deref(), Some("dns.google"));
    }

    #[test]
    fn doh_keeps_full_url() {
        let s = Server::parse("https://dns.google/dns-query").unwrap();
        assert_eq!(s.proto, Proto::Https);
        assert_eq!(s.url.as_deref(), Some("https://dns.google/dns-query"));
        assert_eq!(s.name, "dns.google");
    }

    #[test]
    fn ipv6_literals() {
        let s = Server::parse("[2606:4700:4700::1111]:53").unwrap();
        assert_eq!(s.target, "[2606:4700:4700::1111]:53");
        let s = Server::parse("2606:4700:4700::1111").unwrap();
        assert_eq!(s.target, "[2606:4700:4700::1111]:53");
    }
}
