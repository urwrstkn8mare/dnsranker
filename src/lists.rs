//! Fetching, caching and parsing the two input lists: domains to query and
//! resolvers to query them against.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::server::{Proto, Server};

/// ~10k popular domains, one per line, in popularity order.
pub const DEFAULT_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt";

/// The long tail: a million domains ranked by referring subnets, reaching far
/// enough down that a uniform sample looks nothing like the popular head. About
/// 80 MB, downloaded once and cached, and only when the random pool is in use.
pub const DEFAULT_RANDOM_URL: &str = "https://downloads.majestic.com/majestic_million.csv";

/// Public resolvers with a country attached, one file per country code.
/// Plain DNS only, but it is the piece the provider catalogue lacks: which
/// country a resolver is actually in.
pub const DEFAULT_REGIONAL_URL: &str = "https://public-dns.info/nameserver/{cc}.csv";

/// AdGuard's "Known DNS providers" reference: ~70 providers, each listing its
/// plain-DNS, DoH and DoT endpoints in a markdown table.
pub const DEFAULT_SERVERS_URL: &str = "https://raw.githubusercontent.com/AdguardTeam/KnowledgeBaseDNS/master/docs/general/dns-providers.md";

const FALLBACK_DOMAINS: &str = include_str!("../assets/domains.txt");
const FALLBACK_SERVERS: &str = include_str!("../assets/servers.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    /// Globally distributed anycast resolvers — the well-known public ones.
    Anycast,
    /// Resolvers serving one country or region.
    Regional,
    /// Small hobbyist resolvers.
    Personal,
}

impl Section {
    pub fn parse(s: &str) -> Result<Section> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "anycast" | "public" => Section::Anycast,
            "regional" => Section::Regional,
            "personal" | "small" => Section::Personal,
            other => anyhow::bail!("unknown section '{other}' (anycast, regional or personal)"),
        })
    }
}

/// How aggressively an endpoint filters what it resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Filtering {
    Unfiltered,
    Default,
    Filtered,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub section: Section,
    pub provider: String,
    #[allow(dead_code)]
    pub variant: String,
    pub filtering: Filtering,
    /// ISO country code the resolver is operated from, where it can be
    /// established. `None` means the catalogue gave nothing to go on.
    pub country: Option<String>,
    pub ipv6: bool,
    /// Asked for by name — by `--add` or by /etc/resolv.conf. Pinned entries
    /// skip every filter and survive `--max-servers`, because a resolver the
    /// user named should never silently vanish from the results.
    pub pinned: bool,
    pub server: Server,
}

/// Where a list came from, for the run header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Downloaded,
    Cached,
    Builtin,
    Local,
}

impl Origin {
    pub fn describe(self) -> &'static str {
        match self {
            Origin::Downloaded => "downloaded",
            Origin::Cached => "cached",
            Origin::Builtin => "built-in fallback",
            Origin::Local => "local file",
        }
    }
}

pub fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("DNSRANKER_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("dnsranker")
}

/// Read `name` from the cache, downloading it if missing, stale or `refresh`.
/// A failed download falls back to a stale cache entry before giving up.
pub async fn fetch_cached(
    url: &str,
    name: &str,
    max_age: Duration,
    refresh: bool,
) -> Result<(String, Origin)> {
    let path = cache_dir().join(name);
    let fresh = !refresh
        && std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() < max_age)
            .unwrap_or(false);

    if fresh
        && let Ok(text) = std::fs::read_to_string(&path)
        && !text.trim().is_empty()
    {
        return Ok((text, Origin::Cached));
    }

    match download(url).await {
        Ok(text) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&path, &text).ok();
            Ok((text, Origin::Downloaded))
        }
        Err(e) => match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => Ok((text, Origin::Cached)),
            _ => Err(e),
        },
    }
}

/// Like [`fetch_cached`], but keeps the body on disk and hands back its path.
/// Used for the long-tail list, which is far too big to want in memory.
pub async fn fetch_cached_file(
    url: &str,
    name: &str,
    max_age: Duration,
    refresh: bool,
    on_download: impl FnOnce(),
) -> Result<(PathBuf, Origin)> {
    let path = cache_dir().join(name);
    let fresh = !refresh
        && std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() < max_age)
            .unwrap_or(false);
    if fresh {
        return Ok((path, Origin::Cached));
    }

    on_download();
    match download_to_file(url, &path).await {
        Ok(()) => Ok((path, Origin::Downloaded)),
        // A stale copy beats no copy.
        Err(e) if path.exists() => {
            let _ = e;
            Ok((path, Origin::Cached))
        }
        Err(e) => Err(e),
    }
}

async fn download_to_file(url: &str, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .user_agent(concat!("dnsranker/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()
        .with_context(|| format!("fetching {url}"))?;

    // Write beside the target and rename, so an interrupted download can't
    // leave a half-written list in the cache.
    let tmp = path.with_extension("partial");
    let mut file =
        std::fs::File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    while let Some(chunk) = resp.chunk().await.context("reading response body")? {
        std::io::Write::write_all(&mut file, &chunk).context("writing to cache")?;
    }
    drop(file);
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Uniformly sample `k` domains from a list far too large to hold in memory,
/// in one pass (Algorithm R). `exclude` keeps the sample disjoint from the
/// popular pool.
pub fn sample_domains(
    path: &Path,
    k: usize,
    exclude: &HashSet<String>,
    rng: &mut crate::plan::Rng,
) -> Result<Vec<String>> {
    use std::io::BufRead;

    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let reader = std::io::BufReader::with_capacity(1 << 16, file);

    let mut reservoir: Vec<String> = Vec::with_capacity(k);
    let mut seen: u64 = 0;
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let Some(domain) = parse_domain_line(&line) else {
            continue;
        };
        if exclude.contains(&domain) {
            continue;
        }
        if reservoir.len() < k {
            reservoir.push(domain);
        } else {
            let j = rng.next() % (seen + 1);
            if (j as usize) < k {
                reservoir[j as usize] = domain;
            }
        }
        seen += 1;
    }
    // The reservoir fills in file order; shuffle so a truncated sample isn't
    // just the top of the list.
    rng.shuffle(&mut reservoir);
    Ok(reservoir)
}

async fn download(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .user_agent(concat!("dnsranker/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()
        .with_context(|| format!("fetching {url}"))?;
    resp.text().await.context("reading response body")
}

/// One domain per line; also tolerates `rank,domain` CSV rows and `#` comments.
pub fn parse_domains(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(domain) = parse_domain_line(line)
            && seen.insert(domain.clone())
        {
            out.push(domain);
        }
    }
    out
}

/// Pull the domain out of one line, whether it's bare or a CSV row such as
/// Majestic's `rank,tldrank,domain,tld,...`.
fn parse_domain_line(line: &str) -> Option<String> {
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return None;
    }
    let field = line
        .split([',', ';', '\t', ' '])
        .filter(|f| !f.is_empty())
        .find(|f| f.contains('.') && f.parse::<f64>().is_err())
        .unwrap_or(line);
    let domain = field
        .trim_matches('"')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let plausible = domain.contains('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    plausible.then_some(domain)
}

pub fn fallback_domains() -> Vec<String> {
    parse_domains(FALLBACK_DOMAINS)
}

pub fn fallback_servers() -> Vec<Entry> {
    parse_server_lines(FALLBACK_SERVERS)
}

/// Parse a plain server list: one `Name = spec` (or bare spec) per line.
pub fn parse_server_lines(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = strip_comment(line);
        if line.is_empty() {
            continue;
        }
        if let Ok(server) = Server::parse(line) {
            let ipv6 = server.target.starts_with('[');
            out.push(Entry {
                section: Section::Anycast,
                provider: server.name.clone(),
                variant: String::new(),
                filtering: Filtering::Default,
                country: None,
                ipv6,
                pinned: false,
                server,
            });
        }
    }
    out
}

/// Parse a public-dns.info country file: `ip_address,name,as_number,as_org,
/// country_code,city,version,error,dnssec,reliability,checked_at,created_at`.
///
/// Only fully reliable entries are kept, and only one per network operator —
/// eight resolvers from the same ISP would tell you one thing eight times, and
/// it keeps the scan from leaning on any single network.
pub fn parse_public_dns_csv(text: &str, country: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut seen_orgs = HashSet::new();
    let mut header: Option<Vec<String>> = None;

    for line in text.lines() {
        let fields = split_csv(line);
        let Some(cols) = &header else {
            if fields.iter().any(|f| f == "ip_address") {
                header = Some(fields);
            }
            continue;
        };
        let get = |name: &str| -> &str {
            cols.iter()
                .position(|c| c == name)
                .and_then(|i| fields.get(i))
                .map(String::as_str)
                .unwrap_or("")
        };
        if get("reliability") != "1.00" || get("country_code").to_ascii_uppercase() != country {
            continue;
        }
        let ip = get("ip_address");
        let org = get("as_org").trim().to_string();
        let city = get("city").trim().to_string();
        if ip.is_empty() || org.is_empty() || !seen_orgs.insert(org.to_lowercase()) {
            continue;
        }
        let spec = if ip.contains(':') {
            format!("udp://[{ip}]")
        } else {
            format!("udp://{ip}")
        };
        let Ok(mut server) = Server::parse(&spec) else {
            continue;
        };
        server.name = if city.is_empty() {
            format!("{org} [{country}]")
        } else {
            format!("{org} ({city})")
        };
        let ipv6 = server.target.starts_with('[');
        out.push(Entry {
            section: Section::Regional,
            provider: org,
            variant: String::new(),
            filtering: Filtering::Default,
            country: Some(country.to_string()),
            ipv6,
            pinned: false,
            server,
        });
    }
    out
}

/// Split one CSV row, honouring quoted fields (AS org names contain commas).
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    out.push(field);
    out
}

/// Strip a trailing `#` comment, leaving `tls://1.1.1.1#dns.example` alone:
/// a comment marker only counts at line start or after whitespace.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return line[..i].trim();
        }
    }
    line.trim()
}

/// Parse AdGuard's `dns-providers.md`, one entry per (provider, variant, protocol).
pub fn parse_providers_md(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut section = Section::Anycast;
    let mut provider = String::new();
    let mut variant = String::new();
    // Prose since the last heading. Whether a resolver filters is often only
    // stated here — Quad9's "Standard" reads as neutral until you notice the
    // sentence underneath it promising blocklists.
    let mut blurb = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("## ") {
            let title = clean_heading(rest).to_ascii_lowercase();
            section = if title.contains("anycast") || title.contains("public") {
                Section::Anycast
            } else if title.contains("regional") {
                Section::Regional
            } else {
                Section::Personal
            };
            provider.clear();
            variant.clear();
            blurb.clear();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("### ") {
            provider = clean_heading(rest);
            variant.clear();
            blurb.clear();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("#### ") {
            variant = clean_heading(rest);
            blurb.clear();
            continue;
        }
        if !trimmed.starts_with('|') || provider.is_empty() {
            if !trimmed.is_empty() && !trimmed.starts_with('[') {
                blurb.push(' ');
                blurb.push_str(trimmed);
            }
            continue;
        }

        let cells: Vec<&str> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() < 2 {
            continue;
        }
        let label = cells[0];
        let Some(proto) = protocol_from_label(label) else {
            continue;
        };
        let Some(address) = first_code_span(cells[1]) else {
            continue;
        };
        let Ok(server) = Server::parse(&address) else {
            continue;
        };
        if server.proto != proto {
            continue; // e.g. a `quic://` address in a row we read as DoT
        }

        // Only a literal address fixes the family: a DoH/DoT hostname is listed
        // under both IPv4 and IPv6 headings but is one and the same endpoint.
        let ipv6 = server.target.starts_with('[');
        let filtering = classify(&variant, &blurb);
        let mut name = provider.clone();
        if !variant.is_empty() {
            name.push_str(&format!(" ({variant})"));
        }
        if ipv6 {
            name.push_str(" [v6]");
        }
        out.push(Entry {
            section,
            provider: provider.clone(),
            variant: variant.clone(),
            filtering,
            country: crate::geo::infer(&provider, &blurb, &server.endpoint()),
            ipv6,
            pinned: false,
            server: Server { name, ..server },
        });
    }
    out
}

fn clean_heading(s: &str) -> String {
    s.trim().trim_matches('*').trim().to_string()
}

fn protocol_from_label(label: &str) -> Option<Proto> {
    let l = label.to_ascii_lowercase();
    if l.contains("dnscrypt") || l.contains("quic") || l.contains("odoh") || l.contains("doq") {
        return None;
    }
    if l.contains("https") || l.contains("doh") {
        Some(Proto::Https)
    } else if l.contains("tls") || l.contains("dot") {
        Some(Proto::Tls)
    } else if l.starts_with("dns") || l.contains("plain") {
        Some(Proto::Udp)
    } else {
        None
    }
}

/// Pull the first `` `backticked` `` value out of a table cell.
fn first_code_span(cell: &str) -> Option<String> {
    let start = cell.find('`')? + 1;
    let end = start + cell[start..].find('`')?;
    let value = cell[start..end].trim();
    // DoH rows sometimes carry a URI template suffix, e.g. `/dns-query{?dns}`.
    let value = value.split('{').next().unwrap_or(value).trim();
    if value.is_empty() || value.starts_with("sdns://") {
        None
    } else {
        Some(value.to_string())
    }
}

/// Decide whether an endpoint filters what it resolves, from its variant
/// heading plus the prose the catalogue prints under it.
///
/// A denial always wins over the keywords it contains: "don't provide security
/// blocklists" is a promise *not* to filter, even though it says "blocklists".
fn classify(variant: &str, blurb: &str) -> Filtering {
    // Normalise the typographic apostrophes the catalogue uses, or "don’t"
    // never matches "don't".
    let text = format!("{variant} {blurb}")
        .to_lowercase()
        .replace(['\u{2019}', '\u{02bc}'], "'");

    // Phrases that say "we don't filter" without using either word negatively.
    const DENIALS: [&str; 4] = [
        "resolution only",
        "unsecured",
        "no blocklists",
        "don't provide security",
    ];
    if DENIALS.iter().any(|k| text.contains(k)) || denies_filtering(&text) {
        return Filtering::Unfiltered;
    }

    const BLOCKING: [&str; 15] = [
        "family",
        "adult",
        "child",
        "parental",
        "security",
        "malware",
        "phishing",
        "spyware",
        "safe",
        "protect",
        "kids",
        "block",
        "filter",
        "blocklist",
        "threat",
    ];
    if BLOCKING.iter().any(|k| text.contains(k)) {
        Filtering::Filtered
    } else {
        Filtering::Default
    }
}

/// Is every mention of filtering or blocking a denial of it? Catches the many
/// ways the catalogue phrases it — "unfiltered", "non-filtering", "there is no
/// traffic filtering", "without blocking any specific categories".
fn denies_filtering(text: &str) -> bool {
    const NEGATIONS: [&str; 6] = [" no ", "not ", "n't ", "without ", "never ", "free of "];
    for keyword in ["filter", "block"] {
        let mut from = 0;
        while let Some(rel) = text[from..].find(keyword) {
            let at = from + rel;
            from = at + keyword.len();

            // Prefix forms: unfiltered, non-filtering, unblocked.
            let before = &text[..at];
            if before.ends_with("un") || before.ends_with("non-") || before.ends_with("non") {
                return true;
            }
            // Otherwise look back over the same sentence for a negation, so
            // "there is no charge. We block ads." doesn't read as a denial.
            let sentence_start = before
                .rfind(['.', ';', ':', '!'])
                .map(|i| i + 1)
                .unwrap_or(0);
            let window = &before[sentence_start..];
            if NEGATIONS.iter().any(|n| window.contains(n)) {
                return true;
            }
        }
    }
    false
}

/// Well-known providers, most recognisable first — global ones, then the
/// regional operators worth reaching for. Used only to order the catalogue so
/// that a default (truncated) run covers the resolvers people actually
/// consider, rather than whatever sorts first alphabetically.
const PREFERRED: [&str; 29] = [
    "cloudflare",
    "google",
    "quad9",
    "adguard",
    "opendns",
    "controld",
    "mullvad",
    "nextdns",
    "dns.sb",
    "cleanbrowsing",
    "verisign",
    "comodo",
    "hurricane",
    "wikimedia",
    "yandex",
    "ali dns",
    "dns privacy",
    // Regional operators, so the regional slice of a run is recognisable too.
    "dns4eu",
    "cira",
    "cz.nic",
    "quad101",
    "iij",
    "applied privacy",
    "digitale gesellschaft",
    "switch",
    "cert-ee",
    "libredns",
    "114dns",
    "dnspod",
];

pub fn preference_rank(provider: &str) -> usize {
    let p = provider.to_ascii_lowercase();
    PREFERRED
        .iter()
        .position(|k| p.contains(k))
        .unwrap_or(PREFERRED.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_lists() {
        let d = parse_domains("# comment\ngoogle.com\n1,youtube.com\nGOOGLE.COM\nbroken\n\n");
        assert_eq!(d, vec!["google.com", "youtube.com"]);
    }

    #[test]
    fn parses_provider_tables() {
        let md = "\
## **Public anycast resolvers**

### Example DNS

#### Non-filtering

| Protocol | Address | |
|---|---|---|
| DNS, IPv4 | `9.9.9.9` and `1.2.3.4` | x |
| DNS, IPv6 | `2620:fe::fe` | x |
| DNS-over-HTTPS | `https://dns.example/dns-query{?dns}` | x |
| DNS-over-TLS | `tls://dns.example` | x |
| DNS-over-QUIC | `quic://dns.example` | x |
| DNSCrypt, IPv4 | Provider: `2.dnscrypt.example` IP: `9.9.9.9:5443` | x |
";
        let entries = parse_providers_md(md);
        let protos: Vec<_> = entries.iter().map(|e| e.server.proto).collect();
        assert_eq!(
            protos,
            vec![Proto::Udp, Proto::Udp, Proto::Https, Proto::Tls]
        );
        assert!(entries[1].ipv6);
        assert_eq!(entries[1].server.name, "Example DNS (Non-filtering) [v6]");
        assert_eq!(entries[0].section, Section::Anycast);
        assert_eq!(entries[0].filtering, Filtering::Unfiltered);
        assert_eq!(entries[2].server.name, "Example DNS (Non-filtering)");
        assert_eq!(
            entries[2].server.url.as_deref(),
            Some("https://dns.example/dns-query")
        );
    }

    #[test]
    fn filtering_is_read_from_the_prose_not_just_the_heading() {
        // The variant heading alone says nothing useful here.
        assert_eq!(
            classify(
                "Standard",
                "Regular DNS servers which provide protection from phishing and spyware. \
                 They include blocklists, DNSSEC validation, and other security features."
            ),
            Filtering::Filtered
        );
        assert_eq!(classify("Standard", ""), Filtering::Default);
        assert_eq!(
            classify(
                "Default",
                "These servers block ads, tracking, and phishing."
            ),
            Filtering::Filtered
        );
    }

    #[test]
    fn denials_beat_the_keywords_they_contain() {
        // "don't provide security blocklists" is a promise not to filter, even
        // though it contains two blocking keywords. Note the typographic
        // apostrophe, which is what the catalogue actually uses.
        assert_eq!(
            classify(
                "Unsecured",
                "Unsecured DNS servers don\u{2019}t provide security blocklists, DNSSEC, or EDNS Client Subnet."
            ),
            Filtering::Unfiltered
        );
        assert_eq!(
            classify("Private", "In *Private* mode, DNS resolution only."),
            Filtering::Unfiltered
        );
        assert_eq!(
            classify(
                "Non-filtering",
                "This variant doesn\u{2019}t filter anything."
            ),
            Filtering::Unfiltered
        );
        assert_eq!(
            classify("Basic", "In *Basic* mode, there is no traffic filtering."),
            Filtering::Unfiltered
        );
        assert_eq!(
            classify(
                "Reliability & Performance 1",
                "These servers provide reliable and fast DNS lookups without blocking any specific categories."
            ),
            Filtering::Unfiltered
        );
    }

    #[test]
    fn a_denial_elsewhere_in_the_text_does_not_excuse_filtering() {
        // The negation has to be in the same sentence as the filtering claim.
        assert_eq!(
            classify(
                "Threat Protection",
                "There is no charge for this service. These servers block malicious domains."
            ),
            Filtering::Filtered
        );
    }

    #[test]
    fn parses_public_dns_country_files() {
        let csv = "\
ip_address,name,as_number,as_org,country_code,city,version,error,dnssec,reliability,checked_at,created_at
1.0.0.2,,13335,CLOUDFLARENET,AU,Melbourne,,,true,1.00,2023-03-01T22:46:56Z,2020-09-05T14:05:36Z
139.134.5.51,,1221,Telstra Corporation Ltd,AU,,,,false,1.00,2023-03-01T00:00:00Z,2020-01-01T00:00:00Z
139.134.5.52,,1221,Telstra Corporation Ltd,AU,Sydney,,,false,1.00,2023-03-01T00:00:00Z,2020-01-01T00:00:00Z
220.245.238.14,,7545,\"TPG Telecom, Limited\",AU,Brisbane,,,true,1.00,2023-03-01T00:00:00Z,2020-01-01T00:00:00Z
1.2.3.4,,999,Flaky Net,AU,Perth,,,false,0.65,2023-03-01T00:00:00Z,2020-01-01T00:00:00Z
8.8.8.8,,15169,GOOGLE,US,,,,true,1.00,2023-03-01T00:00:00Z,2020-01-01T00:00:00Z
";
        let entries = parse_public_dns_csv(csv, "AU");
        let names: Vec<&str> = entries.iter().map(|e| e.server.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "CLOUDFLARENET (Melbourne)",
                "Telstra Corporation Ltd [AU]", // no city recorded
                "TPG Telecom, Limited (Brisbane)",
            ],
            "one per operator, unreliable and out-of-country rows dropped"
        );
        assert!(entries.iter().all(|e| e.section == Section::Regional));
        assert_eq!(entries[0].country.as_deref(), Some("AU"));
        assert_eq!(entries[0].server.endpoint(), "udp://1.0.0.2:53");
    }

    #[test]
    fn csv_splitting_handles_quoted_commas() {
        assert_eq!(
            split_csv(r#"a,"b,c",d"#),
            vec!["a".to_string(), "b,c".to_string(), "d".to_string()]
        );
        assert_eq!(
            split_csv(r#"x,"say ""hi""",z"#),
            vec!["x".to_string(), "say \"hi\"".to_string(), "z".to_string()]
        );
    }

    #[test]
    fn catalogue_entries_get_a_country_where_one_can_be_told() {
        let md = "\
## **Regional resolvers**

### CIRA Canadian Shield DNS

| Protocol | Address | |
|---|---|---|
| DNS, IPv4 | `149.112.121.10` | x |

### Mystery DNS

| Protocol | Address | |
|---|---|---|
| DNS, IPv4 | `203.0.113.9` | x |
";
        let entries = parse_providers_md(md);
        assert_eq!(entries[0].country.as_deref(), Some("CA"));
        assert_eq!(entries[1].country, None);
    }

    #[test]
    fn builtin_lists_are_valid() {
        assert!(fallback_domains().len() > 50);
        let servers = fallback_servers();
        assert!(servers.iter().any(|e| e.server.proto == Proto::Udp));
        assert!(servers.iter().any(|e| e.server.proto == Proto::Tls));
        assert!(servers.iter().any(|e| e.server.proto == Proto::Https));
    }
}
