//! EDNS Client Subnet (RFC 7871) checks.
//!
//! ECS doesn't make DNS itself faster — it usually makes it slower, because the
//! resolver can cache less. What it's meant to buy you is a *better answer*: a
//! CDN edge close to your network rather than close to the resolver. So this
//! module measures two separate things:
//!
//!   1. Whether the resolver honours ECS at all, by asking the same name from
//!      two very different client subnets and watching for an echoed scope, or
//!      failing that, for the answers themselves to change.
//!   2. Whether the answers you actually get are any good, by opening a TCP
//!      connection to the addresses the resolver hands back and timing it.
//!
//! (2) is the number that matters for "is this helping my network": it is the
//! first round trip of every connection your machine makes to those services.

use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::dns::{self, Ecs};
use crate::plan::query_id;
use crate::transport::Client;

/// CDN-hosted names whose answers vary by location — the ones where being
/// steered to the right edge actually matters.
pub const DEFAULT_DOMAINS: [&str; 5] = [
    "www.microsoft.com",
    "www.netflix.com",
    "i.ytimg.com",
    "cdn.jsdelivr.net",
    "www.akamai.com",
];

/// Two routed prefixes on different continents. Asking from both is what
/// reveals a resolver that uses ECS without echoing a scope.
const PROBE_SUBNET_A: (&str, u8) = ("208.67.222.0", 24); // OpenDNS, United States
const PROBE_SUBNET_B: (&str, u8) = ("114.114.114.0", 24); // 114DNS, China

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// Echoed an ECS option with a non-zero scope: definitive.
    Echoed,
    /// No scope echoed, but the answers changed with the subnet we claimed.
    Differs,
    /// Same answers from both subnets, no scope: the resolver ignores ECS.
    Ignored,
    /// Couldn't tell — the probe queries failed.
    Unknown,
}

impl Support {
    pub fn label(self) -> &'static str {
        match self {
            Support::Echoed => "yes",
            Support::Differs => "yes*",
            Support::Ignored => "no",
            Support::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EcsReport {
    pub support: Support,
    /// SCOPE PREFIX-LENGTH the resolver echoed, when it echoed one.
    pub scope: Option<u8>,
    /// Median TCP handshake time to the addresses this resolver returned, in
    /// milliseconds — how close the edge it picked actually is.
    pub edge_rtt_ms: Option<f64>,
    pub edge_samples: usize,
    /// One representative address per test domain, for `-v`.
    pub addresses: Vec<String>,
}

pub struct EcsProbe {
    pub domains: Vec<String>,
    pub timeout: Duration,
    /// Port to open when timing the edge; 443 is what a browser would use.
    pub port: u16,
}

impl EcsProbe {
    pub fn new(domains: Vec<String>, timeout: Duration) -> EcsProbe {
        EcsProbe {
            domains,
            timeout,
            port: 443,
        }
    }
}

pub async fn probe(client: &mut Client, probe: &EcsProbe) -> EcsReport {
    let subnet_a = Ecs::new(PROBE_SUBNET_A.0.parse().unwrap(), PROBE_SUBNET_A.1);
    let subnet_b = Ecs::new(PROBE_SUBNET_B.0.parse().unwrap(), PROBE_SUBNET_B.1);

    let mut support = Support::Unknown;
    let mut scope = None;
    let mut addresses = Vec::new();
    let mut rtts: Vec<f64> = Vec::new();

    for domain in &probe.domains {
        // The natural answer: no client subnet claimed, so the resolver decides
        // on its own. This is what your machine would really get.
        let natural = ask(client, domain, None).await;
        if let Some(msg) = &natural {
            if let Some(s) = msg.ecs_scope.filter(|s| *s > 0) {
                support = Support::Echoed;
                scope = Some(s);
            }
            if let Some(addr) = msg.addrs.first() {
                addresses.push(addr.to_string());
                if let Some(ms) = tcp_rtt(*addr, probe.port, probe.timeout).await {
                    rtts.push(ms);
                }
            }
        }

        // Only run the two-subnet comparison until it has told us something;
        // it costs four extra queries per domain otherwise.
        if support == Support::Echoed || support == Support::Differs {
            continue;
        }
        let from_a = ask(client, domain, Some(subnet_a)).await;
        let from_b = ask(client, domain, Some(subnet_b)).await;
        match (from_a, from_b) {
            (Some(a), Some(b)) => {
                if let Some(s) = a.ecs_scope.or(b.ecs_scope).filter(|s| *s > 0) {
                    support = Support::Echoed;
                    scope = Some(s);
                } else if !a.addrs.is_empty() && !b.addrs.is_empty() {
                    let differ = sorted(&a.addrs) != sorted(&b.addrs);
                    support = if differ {
                        Support::Differs
                    } else {
                        Support::Ignored
                    };
                }
            }
            _ => continue,
        }
    }

    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let edge_rtt_ms = match rtts.len() {
        0 => None,
        n => Some(rtts[n / 2]),
    };

    EcsReport {
        support,
        scope,
        edge_rtt_ms,
        edge_samples: rtts.len(),
        addresses,
    }
}

async fn ask(client: &mut Client, domain: &str, ecs: Option<Ecs>) -> Option<dns::Message> {
    let id = query_id();
    let wire = dns::encode_query(id, domain, 1, ecs).ok()?;
    let bytes = client.query_raw(&wire, id).await.ok()?;
    let msg = dns::parse_message(&bytes).ok()?;
    // A SERVFAIL or REFUSED tells us nothing about ECS, and its (absent)
    // addresses would poison the comparison.
    (msg.header.rcode == 0).then_some(msg)
}

fn sorted(addrs: &[IpAddr]) -> Vec<IpAddr> {
    let mut v = addrs.to_vec();
    v.sort();
    v
}

/// Time a TCP handshake to an address the resolver handed us. This is the
/// latency the resolver's choice of edge actually costs you.
async fn tcp_rtt(addr: IpAddr, port: u16, timeout: Duration) -> Option<f64> {
    let target = SocketAddr::new(addr, port);
    let started = Instant::now();
    let connected = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target))
        .await
        .ok()?
        .ok()?;
    let elapsed = started.elapsed();
    drop(connected);
    Some(elapsed.as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_subnets_are_valid_and_distinct() {
        let a = Ecs::new(PROBE_SUBNET_A.0.parse().unwrap(), PROBE_SUBNET_A.1);
        let b = Ecs::new(PROBE_SUBNET_B.0.parse().unwrap(), PROBE_SUBNET_B.1);
        assert_ne!(a.network(), b.network());
        assert_eq!(a.to_string(), "208.67.222.0/24");
    }

    #[test]
    fn support_labels() {
        assert_eq!(Support::Echoed.label(), "yes");
        assert_eq!(Support::Ignored.label(), "no");
    }
}
