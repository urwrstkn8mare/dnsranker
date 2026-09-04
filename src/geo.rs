//! Working out where *you* are, and where a resolver is.
//!
//! The resolver catalogue carries no country field, so an entry's region is
//! inferred from whatever it does say — the provider's name, its description,
//! and the country-code TLD of its endpoint. That covers the resolvers that
//! advertise a country and nothing else, which is why the selection also
//! measures round-trip time: latency is the one signal every resolver gives
//! you, and a resolver on the wrong continent cannot hide it.

use std::time::Duration;

/// Where the user is, and how we worked that out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    /// ISO 3166-1 alpha-2, upper case.
    pub country: String,
    pub source: &'static str,
}

/// Ask Cloudflare's edge which country it sees us from, falling back to the
/// system locale. Returns `None` if neither answers.
pub async fn detect() -> Option<Home> {
    if let Some(country) = from_cloudflare().await {
        return Some(Home {
            country,
            source: "detected",
        });
    }
    from_locale().map(|country| Home {
        country,
        source: "from locale",
    })
}

async fn from_cloudflare() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent(concat!("dnsranker/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    let body = client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    parse_trace(&body)
}

/// The trace endpoint returns `key=value` lines; `loc` is the country.
fn parse_trace(body: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix("loc="))
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 2 && c.chars().all(|c| c.is_ascii_alphabetic()))
}

/// `en_AU.UTF-8` → `AU`.
fn from_locale() -> Option<String> {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        let Ok(value) = std::env::var(var) else {
            continue;
        };
        if let Some(country) = parse_locale(&value) {
            return Some(country);
        }
    }
    None
}

fn parse_locale(value: &str) -> Option<String> {
    let region = value.split(['.', '@']).next()?.split('_').nth(1)?;
    let region = region.trim().to_ascii_uppercase();
    (region.len() == 2 && region.chars().all(|c| c.is_ascii_alphabetic())).then_some(region)
}

/// Countries a pan-European resolver such as DNS4EU serves.
const EUROPE: [&str; 31] = [
    "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR", "HR", "HU",
    "IE", "IS", "IT", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK",
];

/// Does a resolver in `resolver` serve someone in `home`?
pub fn serves(resolver: &str, home: &str) -> bool {
    resolver == home || (resolver == "EU" && EUROPE.contains(&home))
}

/// Country-code TLDs that actually indicate a country. The likes of `.io`,
/// `.co`, `.me`, `.tv` and `.ai` are sold worldwide and say nothing.
const CCTLD: [(&str, &str); 48] = [
    ("au", "AU"),
    ("nz", "NZ"),
    ("jp", "JP"),
    ("cn", "CN"),
    ("tw", "TW"),
    ("kr", "KR"),
    ("hk", "HK"),
    ("sg", "SG"),
    ("in", "IN"),
    ("id", "ID"),
    ("my", "MY"),
    ("th", "TH"),
    ("ph", "PH"),
    ("vn", "VN"),
    ("uk", "GB"),
    ("ie", "IE"),
    ("de", "DE"),
    ("fr", "FR"),
    ("nl", "NL"),
    ("be", "BE"),
    ("ch", "CH"),
    ("at", "AT"),
    ("it", "IT"),
    ("es", "ES"),
    ("pt", "PT"),
    ("se", "SE"),
    ("no", "NO"),
    ("dk", "DK"),
    ("fi", "FI"),
    ("is", "IS"),
    ("pl", "PL"),
    ("cz", "CZ"),
    ("sk", "SK"),
    ("hu", "HU"),
    ("ro", "RO"),
    ("bg", "BG"),
    ("gr", "GR"),
    ("ru", "RU"),
    ("ua", "UA"),
    ("ee", "EE"),
    ("lv", "LV"),
    ("lt", "LT"),
    ("ca", "CA"),
    ("us", "US"),
    ("br", "BR"),
    ("za", "ZA"),
    ("il", "IL"),
    ("tr", "TR"),
];

/// Country words as they appear in provider names and descriptions.
const WORDS: [(&str, &str); 40] = [
    ("australia", "AU"),
    ("new zealand", "NZ"),
    ("japan", "JP"),
    ("china", "CN"),
    ("chinese", "CN"),
    ("taiwan", "TW"),
    ("korea", "KR"),
    ("singapore", "SG"),
    ("india", "IN"),
    ("indonesia", "ID"),
    ("malaysia", "MY"),
    ("thailand", "TH"),
    ("united kingdom", "GB"),
    ("britain", "GB"),
    ("british", "GB"),
    ("ireland", "IE"),
    ("germany", "DE"),
    ("german", "DE"),
    ("france", "FR"),
    ("french", "FR"),
    ("netherlands", "NL"),
    ("switzerland", "CH"),
    ("swiss", "CH"),
    ("austria", "AT"),
    ("italy", "IT"),
    ("spain", "ES"),
    ("sweden", "SE"),
    ("norway", "NO"),
    ("denmark", "DK"),
    ("finland", "FI"),
    ("poland", "PL"),
    ("czech", "CZ"),
    ("greece", "GR"),
    ("russia", "RU"),
    ("ukraine", "UA"),
    ("estonia", "EE"),
    ("canada", "CA"),
    ("canadian", "CA"),
    ("brazil", "BR"),
    ("israel", "IL"),
];

/// Providers whose country is in their name but not spelled out, or stated
/// only by the operator elsewhere.
const NAMED: [(&str, &str); 8] = [
    ("cz.nic", "CZ"),
    ("iij.jp", "JP"),
    ("skydns ru", "RU"),
    ("uk dns", "GB"),
    ("quad101", "TW"),
    ("switch dns", "CH"),
    ("cert-ee", "EE"),
    ("dns4eu", "EU"),
];

/// Best guess at the country a resolver is operated from, or `None` when the
/// catalogue gives nothing to go on.
pub fn infer(name: &str, blurb: &str, endpoint: &str) -> Option<String> {
    let text = format!("{name} {blurb}").to_lowercase();

    if let Some((_, code)) = NAMED.iter().find(|(k, _)| text.contains(k)) {
        return Some((*code).to_string());
    }
    if let Some((_, code)) = WORDS.iter().find(|(k, _)| text.contains(k)) {
        return Some((*code).to_string());
    }

    // Fall back to the endpoint's TLD: `resolver.dnsprivacy.org.uk` → GB.
    let host = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint);
    let host = host.split(['/', '?', '#']).next().unwrap_or(host);
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let tld = host.rsplit('.').next()?.to_ascii_lowercase();
    CCTLD
        .iter()
        .find(|(k, _)| *k == tld)
        .map(|(_, code)| (*code).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_cloudflare_trace() {
        let body = "fl=123\nh=www.cloudflare.com\nip=1.2.3.4\nts=1\nloc=AU\ncolo=PER\n";
        assert_eq!(parse_trace(body).as_deref(), Some("AU"));
        assert_eq!(parse_trace("loc=XX\n").as_deref(), Some("XX"));
        assert_eq!(parse_trace("colo=PER\n"), None);
        // Cloudflare returns an empty loc for some networks.
        assert_eq!(parse_trace("loc=\n"), None);
    }

    #[test]
    fn reads_the_locale() {
        assert_eq!(parse_locale("en_AU.UTF-8").as_deref(), Some("AU"));
        assert_eq!(parse_locale("de_DE@euro").as_deref(), Some("DE"));
        assert_eq!(parse_locale("C.UTF-8"), None);
        assert_eq!(parse_locale("en"), None);
    }

    #[test]
    fn infers_from_names_and_descriptions() {
        assert_eq!(
            infer("CERT-EE", "", "udp://1.1.1.1:53").as_deref(),
            Some("EE")
        );
        assert_eq!(
            infer("CIRA Canadian Shield DNS", "", "udp://1.1.1.1:53").as_deref(),
            Some("CA")
        );
        assert_eq!(
            infer(
                "ByteDance Public DNS",
                "a free DNS service by ByteDance at China",
                "udp://1.1.1.1:53"
            )
            .as_deref(),
            Some("CN")
        );
    }

    #[test]
    fn infers_from_country_code_tlds() {
        assert_eq!(
            infer("Some Resolver", "", "tls://resolver.dnsprivacy.org.uk:853").as_deref(),
            Some("GB")
        );
        assert_eq!(
            infer("NWPS", "", "https://dns.nwps.fi/dns-query").as_deref(),
            Some("FI")
        );
        // Generic TLDs say nothing about location.
        assert_eq!(infer("Seby DNS", "", "tls://dns.seby.io:853"), None);
        assert_eq!(infer("Example", "", "udp://9.9.9.9:53"), None);
    }

    #[test]
    fn pan_european_resolvers_serve_europe() {
        assert!(serves("AU", "AU"));
        assert!(!serves("AU", "NZ"));
        assert!(serves("EU", "DE"));
        assert!(!serves("EU", "AU"));
    }
}
