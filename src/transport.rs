//! One client per worker, speaking Do53/UDP, Do53/TCP, DoT (RFC 7858) or DoH (RFC 8484).
//!
//! Connection setup is deliberately kept outside the timed section: for the
//! stream protocols we establish (and, on failure, re-establish) the connection
//! before starting the clock, so every protocol is measured on the same terms —
//! the round trip of a single query on a warm connection.

use anyhow::{Context, Result, anyhow, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

use crate::dns;
use crate::server::{Proto, Server};

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

#[derive(Debug, Clone, Copy)]
pub struct QueryResult {
    pub elapsed: Duration,
    pub rcode: u8,
    pub answers: u16,
}

/// Shared, cheap-to-clone bits handed to every worker.
#[derive(Clone)]
pub struct Shared {
    pub tls: Arc<rustls::ClientConfig>,
    pub http: reqwest::Client,
    /// Deadline for a single timed query on an established connection.
    pub timeout: Duration,
    /// Deadline for bringing a connection up. Setup costs a TCP handshake plus,
    /// for DoT/DoH, a TLS handshake and possibly a name lookup, so holding it
    /// to the query timeout would wrongly condemn slow-to-connect resolvers.
    pub connect_timeout: Duration,
}

impl Shared {
    pub fn new(timeout: Duration) -> Result<Shared> {
        let connect_timeout = timeout.max(Duration::from_secs(5));
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"dot".to_vec()];

        // The per-request deadline is tightened to `timeout` once the pool has
        // a warm connection; see `Client::exchange`.
        let http = reqwest::Client::builder()
            .timeout(connect_timeout)
            .connect_timeout(connect_timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent(concat!("dnsranker/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building HTTP client")?;

        Ok(Shared {
            tls: Arc::new(tls),
            http,
            timeout,
            connect_timeout,
        })
    }
}

enum Kind {
    Udp {
        addr: SocketAddr,
        sock: Option<UdpSocket>,
    },
    Stream {
        addr: SocketAddr,
        tls_name: Option<String>,
        conn: Option<Box<dyn Stream>>,
    },
    Https {
        url: String,
    },
}

pub struct Client {
    kind: Kind,
    shared: Shared,
}

impl Client {
    pub async fn new(server: &Server, shared: Shared) -> Result<Client> {
        let kind = match server.proto {
            Proto::Https => Kind::Https {
                url: server
                    .url
                    .clone()
                    .ok_or_else(|| anyhow!("DoH server without a URL"))?,
            },
            Proto::Udp => Kind::Udp {
                addr: resolve(&server.target).await?,
                sock: None,
            },
            Proto::Tcp | Proto::Tls => Kind::Stream {
                addr: resolve(&server.target).await?,
                tls_name: server.tls_name.clone(),
                conn: None,
            },
        };
        Ok(Client { kind, shared })
    }

    /// Establish the connection if it isn't up yet. Kept out of the timed
    /// section on purpose, so every protocol is measured on a warm connection.
    pub async fn connect(&mut self) -> Result<()> {
        let deadline = self.shared.connect_timeout;
        match &mut self.kind {
            Kind::Https { .. } => Ok(()),
            Kind::Udp { addr, sock } => {
                if sock.is_none() {
                    let bind: SocketAddr = if addr.is_ipv4() {
                        "0.0.0.0:0".parse().unwrap()
                    } else {
                        "[::]:0".parse().unwrap()
                    };
                    let s = UdpSocket::bind(bind).await.context("binding UDP socket")?;
                    s.connect(*addr).await.context("connecting UDP socket")?;
                    *sock = Some(s);
                }
                Ok(())
            }
            Kind::Stream {
                addr,
                tls_name,
                conn,
            } => {
                if conn.is_some() {
                    return Ok(());
                }
                let tcp = tokio::time::timeout(deadline, TcpStream::connect(*addr))
                    .await
                    .map_err(|_| anyhow!("connect timed out"))?
                    .with_context(|| format!("connecting to {addr}"))?;
                tcp.set_nodelay(true).ok();
                *conn = Some(match tls_name {
                    None => Box::new(tcp) as Box<dyn Stream>,
                    Some(name) => {
                        let sni = rustls::pki_types::ServerName::try_from(name.clone())
                            .with_context(|| format!("invalid TLS name '{name}'"))?;
                        let connector = TlsConnector::from(self.shared.tls.clone());
                        let tls = tokio::time::timeout(deadline, connector.connect(sni, tcp))
                            .await
                            .map_err(|_| anyhow!("TLS handshake timed out"))?
                            .context("TLS handshake failed")?;
                        Box::new(tls) as Box<dyn Stream>
                    }
                });
                Ok(())
            }
        }
    }

    /// Send one query and time the round trip.
    pub async fn query(&mut self, wire: &[u8], id: u16) -> Result<QueryResult> {
        self.exchange(wire, id, self.shared.timeout).await
    }

    /// The opening query against a resolver. It runs on the connect deadline
    /// rather than the query deadline, because for DoH there is no way to bring
    /// the connection up separately — the first request carries the handshake.
    /// Its timing is discarded.
    pub async fn probe(&mut self, wire: &[u8], id: u16) -> Result<QueryResult> {
        self.exchange(wire, id, self.shared.connect_timeout).await
    }

    /// One query returning the raw response bytes, for callers that need the
    /// records rather than just the timing.
    pub async fn query_raw(&mut self, wire: &[u8], id: u16) -> Result<Vec<u8>> {
        self.exchange_raw(wire, id, self.shared.connect_timeout)
            .await
            .map(|(_, bytes)| bytes)
    }

    async fn exchange(&mut self, wire: &[u8], id: u16, timeout: Duration) -> Result<QueryResult> {
        let (elapsed, bytes) = self.exchange_raw(wire, id, timeout).await?;
        let header = dns::parse_header(&bytes)?;
        Ok(QueryResult {
            elapsed,
            rcode: header.rcode,
            answers: header.answers,
        })
    }

    async fn exchange_raw(
        &mut self,
        wire: &[u8],
        id: u16,
        timeout: Duration,
    ) -> Result<(Duration, Vec<u8>)> {
        self.connect().await?;
        let started = Instant::now();

        let result = match &mut self.kind {
            Kind::Udp { sock, .. } => {
                let sock = sock.as_mut().expect("connected above");
                tokio::time::timeout(timeout, udp_exchange(sock, wire, id)).await
            }
            Kind::Stream { conn, .. } => {
                let stream = conn.as_mut().expect("connected above");
                tokio::time::timeout(timeout, stream_exchange(stream, wire, id)).await
            }
            Kind::Https { url } => {
                let req = self
                    .shared
                    .http
                    .post(url.as_str())
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message")
                    .body(wire.to_vec())
                    .timeout(timeout);
                tokio::time::timeout(timeout, doh_exchange(req, id)).await
            }
        };
        let elapsed = started.elapsed();

        match result {
            Ok(Ok(bytes)) => Ok((elapsed, bytes)),
            Ok(Err(e)) => {
                self.reset();
                Err(e)
            }
            Err(_) => {
                self.reset();
                Err(anyhow!("timed out after {}ms", timeout.as_millis()))
            }
        }
    }

    /// Drop a connection that erred so the next query reconnects.
    fn reset(&mut self) {
        match &mut self.kind {
            Kind::Udp { sock, .. } => *sock = None,
            Kind::Stream { conn, .. } => *conn = None,
            Kind::Https { .. } => {}
        }
    }
}

async fn resolve(target: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(target)
        .await
        .with_context(|| format!("resolving {target}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for {target}"))
}

async fn udp_exchange(sock: &mut UdpSocket, wire: &[u8], id: u16) -> Result<Vec<u8>> {
    sock.send(wire).await.context("send failed")?;
    let mut buf = [0u8; 4096];
    // Ignore stray datagrams from earlier, timed-out queries.
    loop {
        let n = sock.recv(&mut buf).await.context("receive failed")?;
        let Ok(header) = dns::parse_header(&buf[..n]) else {
            continue;
        };
        if header.id == id {
            return Ok(buf[..n].to_vec());
        }
    }
}

async fn stream_exchange(stream: &mut Box<dyn Stream>, wire: &[u8], id: u16) -> Result<Vec<u8>> {
    // RFC 1035 / 7858: two-byte big-endian length prefix.
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(wire);
    stream.write_all(&framed).await.context("send failed")?;
    stream.flush().await.context("flush failed")?;

    loop {
        let mut len = [0u8; 2];
        stream
            .read_exact(&mut len)
            .await
            .context("connection closed while reading length")?;
        let len = u16::from_be_bytes(len) as usize;
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .context("connection closed while reading message")?;
        let header = dns::parse_header(&buf)?;
        if header.id == id {
            return Ok(buf);
        }
    }
}

async fn doh_exchange(req: reqwest::RequestBuilder, id: u16) -> Result<Vec<u8>> {
    let resp = req.send().await.context("request failed")?;
    let status = resp.status();
    let body = resp.bytes().await.context("reading response body")?;
    if !status.is_success() {
        bail!("HTTP {}", status.as_u16());
    }
    if dns::parse_header(&body)?.id != id {
        bail!("response ID mismatch");
    }
    Ok(body.to_vec())
}
