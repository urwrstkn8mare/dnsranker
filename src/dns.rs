//! Minimal DNS wire-format encoding/decoding.
//!
//! The hot path only needs to build a question and read the response header, so
//! hand-rolling this is smaller and more predictable than a full resolver
//! stack. `parse_message` walks the records as well, for the ECS checks.

use anyhow::{Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const FLAG_RD: u16 = 0x0100;
const CLASS_IN: u16 = 1;
const EDNS_UDP_SIZE: u16 = 1232;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const OPT_ECS: u16 = 8;

/// Just the response header — all the latency path cares about.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub id: u16,
    pub rcode: u8,
    pub answers: u16,
}

/// A response with its records walked: the addresses it handed back and what
/// it said about EDNS Client Subnet.
#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub addrs: Vec<IpAddr>,
    /// SCOPE PREFIX-LENGTH from the echoed ECS option, if there was one. A
    /// non-zero scope means the answer was actually tailored to the subnet.
    pub ecs_scope: Option<u8>,
}

/// The client subnet to advertise in a query (RFC 7871).
#[derive(Debug, Clone, Copy)]
pub struct Ecs {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Ecs {
    pub fn new(addr: IpAddr, prefix: u8) -> Ecs {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        Ecs {
            addr,
            prefix: prefix.min(max),
        }
    }

    /// The zeroed-out prefix, which is what actually goes on the wire.
    pub fn network(&self) -> IpAddr {
        let bytes = self.addr_bytes();
        let keep = self.prefix as usize;
        match self.addr {
            IpAddr::V4(_) => {
                let mut out = [0u8; 4];
                mask_into(&bytes, keep, &mut out);
                IpAddr::V4(Ipv4Addr::from(out))
            }
            IpAddr::V6(_) => {
                let mut out = [0u8; 16];
                mask_into(&bytes, keep, &mut out);
                IpAddr::V6(Ipv6Addr::from(out))
            }
        }
    }

    fn addr_bytes(&self) -> Vec<u8> {
        match self.addr {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        }
    }
}

impl std::fmt::Display for Ecs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

fn mask_into(src: &[u8], prefix_bits: usize, out: &mut [u8]) {
    for (i, byte) in out.iter_mut().enumerate() {
        let bit = i * 8;
        *byte = if bit + 8 <= prefix_bits {
            src[i]
        } else if bit < prefix_bits {
            src[i] & (0xffu8 << (8 - (prefix_bits - bit)))
        } else {
            0
        };
    }
}

pub fn record_type(name: &str) -> Result<u16> {
    Ok(match name.to_ascii_uppercase().as_str() {
        "A" => TYPE_A,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => TYPE_AAAA,
        "SRV" => 33,
        "HTTPS" => 65,
        other => bail!("unsupported record type: {other}"),
    })
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "RCODE?",
    }
}

/// Build a standard recursive query with an EDNS(0) OPT record, optionally
/// carrying a client subnet.
pub fn encode_query(id: u16, qname: &str, qtype: u16, ecs: Option<Ecs>) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(qname.len() + 48);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&FLAG_RD.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&1u16.to_be_bytes()); // arcount (the OPT below)

    encode_name(&mut buf, qname)?;
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());

    // OPT pseudo-record: root name, type 41, class carries the UDP payload size.
    buf.push(0);
    buf.extend_from_slice(&TYPE_OPT.to_be_bytes());
    buf.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // extended rcode + flags

    let rdata = match ecs {
        None => Vec::new(),
        Some(ecs) => {
            let addr_len = (ecs.prefix as usize).div_ceil(8);
            let (family, bytes): (u16, Vec<u8>) = match ecs.network() {
                IpAddr::V4(a) => (1, a.octets().to_vec()),
                IpAddr::V6(a) => (2, a.octets().to_vec()),
            };
            let mut opt = Vec::with_capacity(8 + addr_len);
            opt.extend_from_slice(&OPT_ECS.to_be_bytes());
            opt.extend_from_slice(&((4 + addr_len) as u16).to_be_bytes());
            opt.extend_from_slice(&family.to_be_bytes());
            opt.push(ecs.prefix);
            opt.push(0); // SCOPE PREFIX-LENGTH is always 0 in a query
            opt.extend_from_slice(&bytes[..addr_len]);
            opt
        }
    };
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rdata);

    Ok(buf)
}

fn encode_name(buf: &mut Vec<u8>, name: &str) -> Result<()> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        buf.push(0);
        return Ok(());
    }
    if name.len() > 253 {
        bail!("name too long: {name}");
    }
    for label in name.split('.') {
        if label.is_empty() {
            bail!("empty label in name: {name}");
        }
        if label.len() > 63 {
            bail!("label too long in name: {name}");
        }
        if !label.is_ascii() {
            bail!("non-ASCII name (IDN must be punycode): {name}");
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(())
}

pub fn parse_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < 12 {
        bail!("short response ({} bytes)", buf.len());
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        bail!("response missing QR bit");
    }
    Ok(Header {
        id: u16::from_be_bytes([buf[0], buf[1]]),
        rcode: (flags & 0x000f) as u8,
        answers: u16::from_be_bytes([buf[6], buf[7]]),
    })
}

/// Walk the whole message: A/AAAA records from the answer section, plus the
/// ECS scope from the OPT record if the resolver echoed one.
pub fn parse_message(buf: &[u8]) -> Result<Message> {
    let header = parse_header(buf)?;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let nscount = u16::from_be_bytes([buf[8], buf[9]]);
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos
            .checked_add(4)
            .filter(|p| *p <= buf.len())
            .unwrap_or(pos);
    }

    let mut addrs = Vec::new();
    let mut ecs_scope = None;
    let total = header.answers as usize + nscount as usize + arcount as usize;
    for i in 0..total {
        if pos >= buf.len() {
            break;
        }
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }
        let rdata = &buf[pos..pos + rdlen];
        let in_answer = i < header.answers as usize;

        match rtype {
            TYPE_A if in_answer && rdlen == 4 => {
                addrs.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            TYPE_AAAA if in_answer && rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            TYPE_OPT => ecs_scope = ecs_scope.or_else(|| find_ecs_scope(rdata)),
            _ => {}
        }
        pos += rdlen;
    }

    Ok(Message {
        header,
        addrs,
        ecs_scope,
    })
}

fn find_ecs_scope(rdata: &[u8]) -> Option<u8> {
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            break;
        }
        // FAMILY (2) + SOURCE PREFIX-LENGTH (1) + SCOPE PREFIX-LENGTH (1)
        if code == OPT_ECS && len >= 4 {
            return Some(rdata[pos + 3]);
        }
        pos += len;
    }
    None
}

/// Step over a (possibly compressed) name, returning the offset just past it.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    let mut steps = 0;
    loop {
        if pos >= buf.len() {
            bail!("name runs past end of message");
        }
        let len = buf[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // A compression pointer is always the last thing in a name.
            return Ok(pos + 2);
        }
        pos += 1 + len;
        steps += 1;
        if steps > 128 {
            bail!("malformed name");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_question_section() {
        let q = encode_query(0xbeef, "example.com", 1, None).unwrap();
        assert_eq!(&q[0..2], &[0xbe, 0xef]);
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        assert_eq!(
            &q[12..],
            b"\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
        );
    }

    #[test]
    fn rejects_bad_names() {
        assert!(encode_query(1, "a..b", 1, None).is_err());
        assert!(encode_query(1, &"x".repeat(64), 1, None).is_err());
    }

    #[test]
    fn encodes_client_subnet() {
        let ecs = Ecs::new("203.0.113.77".parse().unwrap(), 24);
        assert_eq!(ecs.network().to_string(), "203.0.113.0");
        let q = encode_query(1, "a.example", 1, Some(ecs)).unwrap();
        // OPT rdata: option 8, length 7, family 1, source /24, scope 0, 3 bytes
        let tail = &q[q.len() - 13..];
        assert_eq!(
            tail,
            &[0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113],
            "unexpected OPT rdata: {tail:?}"
        );
    }

    #[test]
    fn masks_partial_prefixes() {
        let ecs = Ecs::new("192.168.255.255".parse().unwrap(), 20);
        assert_eq!(ecs.network().to_string(), "192.168.240.0");
    }

    #[test]
    fn parses_header() {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0x8183u16.to_be_bytes()); // QR + RD + RA + NXDOMAIN
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        let r = parse_header(&buf).unwrap();
        assert_eq!(r.id, 0x1234);
        assert_eq!(r.rcode, 3);
        assert_eq!(r.answers, 2);
    }

    /// Header + question + one A answer (compressed name) + an OPT with ECS.
    fn sample_response() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x4242u16.to_be_bytes());
        b.extend_from_slice(&0x8180u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes()); // qd
        b.extend_from_slice(&1u16.to_be_bytes()); // an
        b.extend_from_slice(&0u16.to_be_bytes()); // ns
        b.extend_from_slice(&1u16.to_be_bytes()); // ar
        b.extend_from_slice(b"\x03www\x07example\x03com\x00");
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        // answer, name as a compression pointer to offset 12
        b.extend_from_slice(&[0xc0, 0x0c]);
        b.extend_from_slice(&1u16.to_be_bytes()); // A
        b.extend_from_slice(&1u16.to_be_bytes()); // IN
        b.extend_from_slice(&60u32.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&[93, 184, 216, 34]);
        // OPT with an echoed ECS option, scope /24
        b.push(0);
        b.extend_from_slice(&TYPE_OPT.to_be_bytes());
        b.extend_from_slice(&1232u16.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&11u16.to_be_bytes());
        b.extend_from_slice(&OPT_ECS.to_be_bytes());
        b.extend_from_slice(&7u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[24, 24, 203, 0, 113]);
        b
    }

    #[test]
    fn parses_answers_and_ecs_scope() {
        let msg = parse_message(&sample_response()).unwrap();
        assert_eq!(msg.header.id, 0x4242);
        assert_eq!(msg.addrs, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        assert_eq!(msg.ecs_scope, Some(24));
    }

    #[test]
    fn truncated_messages_do_not_panic() {
        let full = sample_response();
        for cut in 12..full.len() {
            let _ = parse_message(&full[..cut]);
        }
    }
}
