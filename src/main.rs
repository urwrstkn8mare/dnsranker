//! dnsranker — measure and rank DNS resolvers (Do53, DoT, DoH) by the latency
//! they deliver on real-world domains.

mod dns;
mod ecs;
mod geo;
mod lists;
mod live;
mod plan;
mod report;
mod server;
mod stats;
mod transport;

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

use lists::{Entry, Filtering, Origin, Section};
use live::{Live, Screen};
use plan::{Job, Pool, Rng};
use report::{Paint, SortKey, TableOpts};
use server::{Proto, Server};
use transport::{Client, Shared};

#[derive(Parser, Debug)]
#[command(
    name = "dnsranker",
    version,
    about = "Rank DNS resolvers (plain, DoT, DoH) by the latency they deliver on real domains",
    long_about = None,
    after_help = SPEC_HELP,
)]
struct Cli {
    /// Resolver specs to test. Replaces the catalogue unless --add is given;
    /// with no specs at all, the downloaded catalogue is used.
    servers: Vec<String>,

    // ---- resolver selection ----
    /// Test the given specs *in addition to* the catalogue, rather than
    /// instead of it
    #[arg(short = 'a', long)]
    add: bool,

    /// Read resolver specs from a file (one per line, `Name = spec` allowed)
    #[arg(short = 'S', long, value_name = "FILE")]
    servers_file: Option<std::path::PathBuf>,

    /// URL of the resolver catalogue to download
    #[arg(long, value_name = "URL", default_value = lists::DEFAULT_SERVERS_URL)]
    servers_url: String,

    /// Protocols to include: udp, tcp, dot, doh
    #[arg(
        long,
        value_name = "LIST",
        default_value = "udp,dot,doh",
        value_delimiter = ','
    )]
    proto: Vec<String>,

    /// Catalogue sections to include: anycast, regional, personal
    #[arg(
        long,
        value_name = "LIST",
        default_value = "anycast,regional",
        value_delimiter = ','
    )]
    section: Vec<String>,

    /// How many of the --max-servers slots are reserved for resolvers in your
    /// own country, so global providers can't crowd them out
    #[arg(long, value_name = "N", default_value_t = 8)]
    regional: usize,

    /// Country whose resolvers count as regional: an ISO code such as AU,
    /// `auto` to detect it, or `any` to accept every region
    #[arg(long, value_name = "CODE", default_value = "auto")]
    country: String,

    /// URL of the per-country resolver list; {cc} is the country code
    #[arg(long, value_name = "URL", default_value = lists::DEFAULT_REGIONAL_URL)]
    regional_url: String,

    /// Only keep resolvers whose name matches this (case-insensitive, repeatable)
    #[arg(long, value_name = "TEXT")]
    filter: Vec<String>,

    /// Maximum resolvers to test, 0 for no limit
    #[arg(short = 'n', long, value_name = "N", default_value_t = 30)]
    max_servers: usize,

    /// Also test resolvers that filter (ad-blocking, malware, family). Off by
    /// default: filtering changes what gets answered, not just how fast
    #[arg(long)]
    include_filtered: bool,

    /// IPv6 endpoints: auto (only if reachable), yes, or no
    #[arg(long, value_name = "MODE", default_value = "auto")]
    ipv6: String,

    /// Skip the system resolvers from /etc/resolv.conf
    #[arg(long)]
    no_system: bool,

    /// Print the selected resolvers and exit
    #[arg(long)]
    list_servers: bool,

    // ---- domains ----
    /// Domain pools to query: popular, random
    #[arg(
        long,
        value_name = "LIST",
        default_value = "popular,random",
        value_delimiter = ','
    )]
    pools: Vec<String>,

    /// Domains in *each* pool
    #[arg(short = 'd', long, value_name = "N", default_value_t = 20)]
    domains: usize,

    /// Read the popular pool from a file instead of the downloaded list
    #[arg(short = 'D', long, value_name = "FILE")]
    domains_file: Option<std::path::PathBuf>,

    /// URL of the popular domain list
    #[arg(long, value_name = "URL", default_value = lists::DEFAULT_DOMAINS_URL)]
    domains_url: String,

    /// URL of the long-tail list the random pool is sampled from
    #[arg(long, value_name = "URL", default_value = lists::DEFAULT_RANDOM_URL)]
    random_url: String,

    /// Seed for the random pool; 0 draws a fresh sample every run
    #[arg(long, value_name = "N", default_value_t = 0)]
    seed: u64,

    // ---- measurement ----
    /// Queries per domain
    #[arg(short = 'r', long, value_name = "N", default_value_t = 1)]
    runs: usize,

    /// Concurrent queries per resolver
    #[arg(short = 'c', long, value_name = "N", default_value_t = 8)]
    concurrency: usize,

    /// Per-query timeout in milliseconds
    #[arg(short = 't', long, value_name = "MS", default_value_t = 2000)]
    timeout: u64,

    /// Record type to query
    #[arg(long = "type", value_name = "RR", default_value = "A")]
    rtype: String,

    /// Resolvers benchmarked at the same time (1 keeps the comparison fair)
    #[arg(long, value_name = "N", default_value_t = 1)]
    parallel_servers: usize,

    /// Prefix a random label to every name, forcing full recursion (measures
    /// cold-cache performance rather than cache hits)
    #[arg(long)]
    uncached: bool,

    /// Re-download the domain and resolver lists even if cached
    #[arg(long)]
    refresh: bool,

    // ---- ECS ----
    /// Check EDNS Client Subnet support, and time a TCP handshake to the CDN
    /// addresses each resolver returns. On by default
    #[arg(long, overrides_with = "no_ecs")]
    ecs: bool,

    /// Skip the client-subnet and edge-latency checks
    #[arg(long, overrides_with = "ecs")]
    no_ecs: bool,

    /// CDN domains used for the ECS and edge-latency checks
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    ecs_domains: Vec<String>,

    // ---- output ----
    /// Sort by: avg, median, p95, min, max, success, popular, random, delta
    #[arg(long, value_name = "KEY", default_value = "avg")]
    sort: String,

    /// Print results as JSON
    #[arg(long)]
    json: bool,

    /// Also write results to a CSV file
    #[arg(long, value_name = "FILE")]
    csv: Option<std::path::PathBuf>,

    /// Show endpoints and per-resolver error breakdowns
    #[arg(short, long)]
    verbose: bool,

    /// Suppress the live table and progress output
    #[arg(short, long)]
    quiet: bool,
}

const SPEC_HELP: &str = "\
RESOLVER SPECS:
  1.1.1.1                      plain DNS over UDP, port 53
  udp://9.9.9.9:5353           plain DNS on a non-standard port
  tcp://8.8.8.8                plain DNS over TCP
  tls://dns.google             DNS-over-TLS, port 853
  tls://8.8.8.8#dns.google     DoT by IP, pinning the certificate name
  https://dns.google/dns-query DNS-over-HTTPS
  2606:4700:4700::1111         IPv6 works bare; bracket it only to add a port
  Name = <spec>                label the endpoint for the results table

EXAMPLES:
  dnsranker                                   rank the default catalogue
  dnsranker 1.1.1.1 8.8.8.8 tls://dns.google  just these three
  dnsranker -a udp://10.0.0.53                the catalogue plus your own
  dnsranker -d 100 -r 3 --uncached            heavier, cold-cache run
  dnsranker --no-ecs                          skip the client-subnet checks
  dnsranker --json > results.json             machine-readable output";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ipv6Mode {
    Auto,
    Yes,
    No,
}

struct Config {
    concurrency: usize,
    timeout: Duration,
    qtype: u16,
}

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}

async fn run(cli: Cli) -> Result<i32> {
    let sort_key = SortKey::parse(&cli.sort)?;
    let qtype = dns::record_type(&cli.rtype)?;
    let pools: Vec<Pool> = {
        let mut p: Vec<Pool> = cli
            .pools
            .iter()
            .map(|s| Pool::parse(s))
            .collect::<Result<_>>()?;
        p.dedup();
        if p.is_empty() {
            bail!("--pools needs at least one of: popular, random");
        }
        p
    };
    let ipv6_mode = match cli.ipv6.to_ascii_lowercase().as_str() {
        "auto" => Ipv6Mode::Auto,
        "yes" | "y" | "true" | "on" => Ipv6Mode::Yes,
        "no" | "n" | "false" | "off" => Ipv6Mode::No,
        other => bail!("--ipv6 expects auto, yes or no (got '{other}')"),
    };
    if cli.concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    if cli.runs == 0 {
        bail!("--runs must be at least 1");
    }
    if cli.domains == 0 {
        bail!("--domains must be at least 1");
    }
    if cli.add && cli.servers.is_empty() {
        bail!("--add needs at least one resolver spec, e.g. `dnsranker --add udp://10.0.0.53`");
    }

    let quiet = cli.quiet || cli.json;
    let log = |msg: &str| {
        if !quiet {
            eprintln!("{msg}");
        }
    };

    // ---- domains ----
    let seed = if cli.seed == 0 {
        plan::random_seed()
    } else {
        cli.seed
    };
    let mut rng = Rng::new(seed);
    let (popular, random, sources) = load_pools(&cli, &pools, &mut rng, &log).await?;

    // ---- resolvers ----
    let ipv6_ok = match ipv6_mode {
        Ipv6Mode::Yes => true,
        Ipv6Mode::No => false,
        Ipv6Mode::Auto => probe_ipv6().await,
    };
    let home = resolve_home(&cli.country).await?;
    let (servers, servers_origin, skipped_v6) = load_servers(&cli, ipv6_ok, home.as_ref()).await?;
    if servers.is_empty() {
        bail!("no resolvers left after filtering — loosen --proto/--section/--filter");
    }

    if cli.list_servers {
        for s in &servers {
            // The `Name = spec` form that --servers-file reads back, so a
            // selection can be saved, edited and re-used as a list.
            println!("{:<40} = {}", s.name, s.endpoint());
        }
        return Ok(0);
    }

    let jobs = Arc::new(plan::build(
        &popular,
        &random,
        cli.runs,
        cli.uncached,
        &mut rng,
    ));
    let cfg = Arc::new(Config {
        concurrency: cli.concurrency,
        timeout: Duration::from_millis(cli.timeout),
        qtype,
    });

    log(&format!(
        "dnsranker: {} resolvers × {} domains × {} run(s) = {} queries",
        servers.len(),
        popular.len() + random.len(),
        cli.runs,
        servers.len() * jobs.len(),
    ));
    log(&format!("  {sources}"));
    log(&format!(
        "  resolvers: {}   region: {}   IPv6: {}{}",
        servers_origin.describe(),
        match &home {
            Some(h) => format!("{} ({})", h.country, h.source),
            None => "any".to_string(),
        },
        if ipv6_ok { "included" } else { "skipped" },
        if skipped_v6 > 0 && !ipv6_ok {
            format!(" ({skipped_v6} endpoints, no IPv6 route from this host)")
        } else {
            String::new()
        },
    ));
    if cli.uncached {
        log("  mode: cold cache (random labels force full recursion)");
    }
    log("");

    // ---- run ----
    let shared = Shared::new(cfg.timeout)?;
    let state: live::Handle = Arc::new(Mutex::new(Live::new(&servers, jobs.clone())));

    // Ctrl-C stops the run without discarding it: in-flight queries are
    // abandoned, untested resolvers are skipped, and whatever was measured so
    // far still gets reported. A second Ctrl-C exits immediately.
    let (cancel_tx, cancel_rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_tx.send_replace(true);
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(130);
            }
        }
    });

    // ECS is checked unless it's explicitly turned off.
    let ecs_enabled = !cli.no_ecs;
    let ecs_probe = ecs_enabled.then(|| {
        let domains = if cli.ecs_domains.is_empty() {
            ecs::DEFAULT_DOMAINS.iter().map(|d| d.to_string()).collect()
        } else {
            cli.ecs_domains.clone()
        };
        Arc::new(ecs::EcsProbe::new(domains, cfg.timeout))
    });

    let painter = Paint::new();
    let live_view = spawn_live_view(state.clone(), &pools, sort_key, ecs_enabled, quiet);

    let lanes = cli.parallel_servers.max(1);
    let mut tested = 0usize;
    for chunk in servers.chunks(lanes).enumerate().collect::<Vec<_>>() {
        let (chunk_index, chunk) = chunk;
        if *cancel_rx.borrow() {
            break;
        }
        let mut handles = Vec::new();
        for (offset, srv) in chunk.iter().enumerate() {
            let row = chunk_index * lanes + offset;
            let (srv, jobs, cfg, shared, cancel, state, ecs_probe) = (
                srv.clone(),
                jobs.clone(),
                cfg.clone(),
                shared.clone(),
                cancel_rx.clone(),
                state.clone(),
                ecs_probe.clone(),
            );
            handles.push(tokio::spawn(async move {
                bench_server(row, &srv, jobs, cfg, shared, cancel, state, ecs_probe).await
            }));
        }
        for h in handles {
            h.await.context("benchmark task panicked")?;
            tested += 1;
        }
    }

    let interrupted = *cancel_rx.borrow();
    if let Some(view) = live_view {
        view.stop().await;
    }

    // ---- output ----
    let mut reports = state.lock().unwrap().reports(interrupted);
    report::sort(&mut reports, sort_key);

    if interrupted {
        log(&format!(
            "interrupted — partial results for {} of {} resolvers ({} untested)",
            reports.len(),
            servers.len(),
            servers.len().saturating_sub(tested),
        ));
        if reports.is_empty() {
            log("nothing was measured before the interrupt");
            return Ok(130);
        }
    }

    if let Some(path) = &cli.csv {
        report::write_csv(path, &reports, &pools)?;
        log(&format!("wrote {}", path.display()));
    }
    if cli.json {
        let meta = serde_json::json!({
            "resolvers": servers.len(),
            "pools": pools.iter().map(|p| p.key()).collect::<Vec<_>>(),
            "domains_per_pool": cli.domains,
            "runs_per_domain": cli.runs,
            "queries_per_resolver": jobs.len(),
            "record_type": cli.rtype.to_uppercase(),
            "concurrency": cli.concurrency,
            "timeout_ms": cli.timeout,
            "uncached": cli.uncached,
            "ipv6": ipv6_ok,
            "ecs": ecs_enabled,
            "seed": seed,
            "sort": cli.sort,
            "interrupted": interrupted,
        });
        println!("{}", report::to_json(&reports, &meta)?);
    } else {
        let opts = TableOpts {
            pools: &pools,
            verbose: cli.verbose,
            ecs: ecs_enabled,
            width: report::terminal_width(),
            max_rows: None,
            paint: &painter,
        };
        for line in report::render_table(&reports, &opts) {
            println!("{line}");
        }
        println!();
        for line in report::legend(&reports, &opts) {
            println!("{line}");
        }
        if let Some(note) = report::loss_warning(&reports, &painter) {
            println!("{note}");
        }
        if cli.seed != 0 || pools.contains(&Pool::Random) {
            println!(
                "{}",
                painter.dim(&format!(
                    "random pool seed: {seed} (pass --seed {seed} to repeat this sample)"
                ))
            );
        }
    }
    Ok(if interrupted { 130 } else { 0 })
}

/// The background task that redraws the ranking while the run is in progress.
struct LiveView {
    stop: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl LiveView {
    async fn stop(self) {
        self.stop.send_replace(true);
        let _ = self.handle.await;
    }
}

fn spawn_live_view(
    state: live::Handle,
    pools: &[Pool],
    sort_key: SortKey,
    ecs: bool,
    quiet: bool,
) -> Option<LiveView> {
    let mut screen = Screen::new(!quiet);
    if !screen.is_enabled() {
        return None;
    }
    let pools = pools.to_vec();
    let (stop, mut stopped) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let paint = Paint::new();
        loop {
            let done = *stopped.borrow();
            {
                let live = state.lock().unwrap();
                let mut reports = live.reports(false);
                report::sort(&mut reports, sort_key);
                let mut lines = report::render_table(
                    &reports,
                    &TableOpts {
                        pools: &pools,
                        verbose: false,
                        ecs,
                        width: screen.width(),
                        max_rows: Some(screen.budget()),
                        paint: &paint,
                    },
                );
                lines.push(status_line(&live, &paint));
                screen.draw(&lines);
            }
            if done {
                break;
            }
            tokio::select! {
                _ = stopped.changed() => {}
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
        // Hand the terminal back so the final table prints from a clean slate.
        screen.clear();
    });
    Some(LiveView { stop, handle })
}

fn status_line(live: &Live, paint: &Paint) -> String {
    let elapsed = live.elapsed().as_secs();
    let pct = if live.total == 0 {
        100.0
    } else {
        live.completed as f64 / live.total as f64 * 100.0
    };
    let bar_width = 20usize;
    let filled = ((pct / 100.0) * bar_width as f64).round() as usize;
    let bar = format!(
        "{}{}",
        "━".repeat(filled.min(bar_width)),
        "─".repeat(bar_width.saturating_sub(filled))
    );
    let _ = paint;
    format!(
        "  {bar} {:>3.0}%  {}/{} queries  {}m{:02}s",
        pct,
        live.completed,
        live.total,
        elapsed / 60,
        elapsed % 60
    )
}

/// Load both domain pools, returning them plus a one-line description of where
/// they came from.
async fn load_pools(
    cli: &Cli,
    pools: &[Pool],
    rng: &mut Rng,
    log: &impl Fn(&str),
) -> Result<(Vec<String>, Vec<String>, String)> {
    let want_popular = pools.contains(&Pool::Popular);
    let want_random = pools.contains(&Pool::Random);

    let (ranked, ranked_origin) = load_ranked(cli).await?;
    if ranked.is_empty() {
        bail!("domain list is empty");
    }

    let popular: Vec<String> = if want_popular {
        ranked.iter().take(cli.domains).cloned().collect()
    } else {
        Vec::new()
    };
    let exclude: HashSet<String> = popular.iter().cloned().collect();

    let mut random = Vec::new();
    let mut random_note = String::new();
    if want_random {
        // The long tail is a separate, much larger list: a sample of the
        // popular list's own tail would still be a sample of popular domains.
        match lists::fetch_cached_file(
            &cli.random_url,
            "long-tail.csv",
            Duration::from_secs(90 * 86400),
            cli.refresh,
            || log("  fetching the long-tail domain list (~80 MB, cached for later runs)…"),
        )
        .await
        {
            Ok((path, origin)) => {
                random = lists::sample_domains(&path, cli.domains, &exclude, rng)?;
                random_note = format!("random: {} of ~1M ({})", random.len(), origin.describe());
            }
            Err(e) => {
                log(&format!(
                    "warning: {e:#}; sampling the random pool from the popular list instead"
                ));
            }
        }
        if random.is_empty() {
            // Fall back to the tail of the ranked list — narrower, but honest
            // about it in the header.
            let mut tail: Vec<String> = ranked
                .iter()
                .skip(popular.len())
                .filter(|d| !exclude.contains(*d))
                .cloned()
                .collect();
            rng.shuffle(&mut tail);
            tail.truncate(cli.domains);
            random = tail;
            random_note = format!("random: {} from the ranked list's tail", random.len());
        }
    }

    let mut parts = Vec::new();
    if want_popular {
        parts.push(format!(
            "popular: top {} ({})",
            popular.len(),
            ranked_origin.describe()
        ));
    }
    if want_random {
        parts.push(random_note);
    }
    Ok((popular, random, format!("domains — {}", parts.join("   "))))
}

async fn load_ranked(cli: &Cli) -> Result<(Vec<String>, Origin)> {
    if let Some(path) = &cli.domains_file {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        return Ok((lists::parse_domains(&text), Origin::Local));
    }
    match lists::fetch_cached(
        &cli.domains_url,
        "domains.txt",
        Duration::from_secs(30 * 86400),
        cli.refresh,
    )
    .await
    {
        Ok((text, origin)) => {
            let domains = lists::parse_domains(&text);
            if domains.is_empty() {
                Ok((lists::fallback_domains(), Origin::Builtin))
            } else {
                Ok((domains, origin))
            }
        }
        Err(e) => {
            if !cli.quiet && !cli.json {
                eprintln!("warning: {e:#}; using the built-in domain list");
            }
            Ok((lists::fallback_domains(), Origin::Builtin))
        }
    }
}

/// Returns the selected resolvers, where the catalogue came from, and how many
/// IPv6 endpoints were dropped for lack of connectivity.
async fn load_servers(
    cli: &Cli,
    ipv6_ok: bool,
    home: Option<&geo::Home>,
) -> Result<(Vec<Server>, Origin, usize)> {
    // Explicit specs on the command line replace the catalogue, unless --add
    // asked for them to be layered on top of it.
    if !cli.servers.is_empty() && !cli.add {
        let mut out = Vec::new();
        for spec in &cli.servers {
            out.push(Server::parse(spec)?);
        }
        return Ok((out, Origin::Local, 0));
    }

    let (mut entries, origin) = if let Some(path) = &cli.servers_file {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        (lists::parse_server_lines(&text), Origin::Local)
    } else {
        match lists::fetch_cached(
            &cli.servers_url,
            "dns-providers.md",
            Duration::from_secs(7 * 86400),
            cli.refresh,
        )
        .await
        {
            Ok((text, origin)) => {
                // A custom --servers-url may serve either the AdGuard provider
                // tables or a plain `Name = spec` list.
                let mut parsed = lists::parse_providers_md(&text);
                if parsed.is_empty() {
                    parsed = lists::parse_server_lines(&text);
                }
                if parsed.is_empty() {
                    (lists::fallback_servers(), Origin::Builtin)
                } else {
                    (parsed, origin)
                }
            }
            Err(e) => {
                if !cli.quiet && !cli.json {
                    eprintln!("warning: {e:#}; using the built-in resolver list");
                }
                (lists::fallback_servers(), Origin::Builtin)
            }
        }
    };

    // The provider catalogue has no country field, so the resolvers that are
    // actually *near* the user come from a per-country list instead.
    if let Some(home) = home
        && cli.regional > 0
        && cli.servers_file.is_none()
    {
        let url = cli
            .regional_url
            .replace("{cc}", &home.country.to_lowercase());
        match lists::fetch_cached(
            &url,
            &format!("regional-{}.csv", home.country.to_lowercase()),
            Duration::from_secs(30 * 86400),
            cli.refresh,
        )
        .await
        {
            Ok((text, _)) => entries.extend(lists::parse_public_dns_csv(&text, &home.country)),
            Err(e) => {
                if !cli.quiet && !cli.json {
                    eprintln!("warning: {e:#}; no in-country resolver list available");
                }
            }
        }
    }

    // Pinned entries go in front: the ones the user named, then their own
    // resolvers as the baseline everything else is compared to.
    let mut pinned = Vec::new();
    for spec in &cli.servers {
        pinned.push(pin(Server::parse(spec)?));
    }
    if !cli.no_system {
        pinned.extend(system_resolvers());
    }
    if !pinned.is_empty() {
        pinned.append(&mut entries);
        entries = pinned;
    }

    let protos: HashSet<Proto> = cli
        .proto
        .iter()
        .map(|p| Proto::parse(p))
        .collect::<Result<_>>()?;
    let sections: HashSet<Section> = cli
        .section
        .iter()
        .map(|s| Section::parse(s))
        .collect::<Result<_>>()?;
    let filters: Vec<String> = cli.filter.iter().map(|f| f.to_lowercase()).collect();

    let mut skipped_v6 = 0usize;
    let mut kept: Vec<Entry> = entries
        .into_iter()
        .filter(|e| {
            if e.pinned {
                return true;
            }
            if e.ipv6 && !ipv6_ok {
                skipped_v6 += 1;
                return false;
            }
            // "Regional" only means anything relative to where you are: a
            // resolver in another hemisphere is just a slow global one. With a
            // known region, keep only the resolvers that serve it — including
            // dropping those whose country can't be established at all.
            if e.section != Section::Anycast
                && let Some(home) = home
            {
                match &e.country {
                    Some(c) if geo::serves(c, &home.country) => {}
                    _ => return false,
                }
            }
            protos.contains(&e.server.proto)
                && sections.contains(&e.section)
                && (cli.include_filtered || e.filtering != Filtering::Filtered)
                && (filters.is_empty() || {
                    let hay = format!("{} {}", e.server.name, e.server.endpoint()).to_lowercase();
                    filters.iter().any(|f| hay.contains(f))
                })
        })
        .collect();

    // One endpoint per provider, protocol and address family, preferring the
    // provider's unfiltered variant.
    kept.sort_by(|a, b| {
        a.provider
            .cmp(&b.provider)
            .then(a.server.proto.cmp(&b.server.proto))
            .then(a.ipv6.cmp(&b.ipv6))
            // A pinned entry outranks the catalogue's take on the same
            // provider, so naming one never removes it from the run.
            .then(b.pinned.cmp(&a.pinned))
            .then(a.filtering.cmp(&b.filtering))
    });
    kept.dedup_by(|a, b| {
        a.provider == b.provider && a.server.proto == b.server.proto && a.ipv6 == b.ipv6
    });

    // Then order so that a truncated run still covers the best-known providers;
    // unranked providers follow alphabetically. Pinned entries lead, so they
    // survive truncation and win the endpoint de-duplication below against an
    // identical catalogue entry.
    let rank = |e: &Entry| {
        if e.pinned {
            0
        } else {
            lists::preference_rank(&e.provider) + 1
        }
    };
    kept.sort_by(|a, b| {
        rank(a)
            .cmp(&rank(b))
            .then(a.provider.cmp(&b.provider))
            .then(a.ipv6.cmp(&b.ipv6))
            .then(a.server.proto.cmp(&b.server.proto))
    });

    // The catalogue lists some endpoints more than once (a DoH URL appears
    // under both the IPv4 and IPv6 headings, for instance).
    let mut seen = HashSet::new();
    kept.retain(|e| seen.insert((e.server.proto, e.server.endpoint())));

    // Check the in-country candidates are still alive, and put the nearest
    // first, before they compete for the reserved slots.
    if cli.regional > 0 && home.is_some() {
        let (mut candidates, rest): (Vec<Entry>, Vec<Entry>) = kept
            .into_iter()
            .partition(|e| !e.pinned && e.section != Section::Anycast);
        // A big country file can list a lot of operators; probing every one
        // would be a burst out of proportion to the eight slots on offer.
        candidates.truncate(120);
        let screener = Shared::new(Duration::from_millis(1500))?;
        let candidates = screen_candidates(candidates, &screener).await;
        kept = rest;
        kept.extend(candidates);
    }

    let kept = apply_budget(kept, cli.max_servers, cli.regional);

    Ok((
        kept.into_iter().map(|e| e.server).collect(),
        origin,
        skipped_v6,
    ))
}

/// Work out which country's resolvers count as local.
async fn resolve_home(setting: &str) -> Result<Option<geo::Home>> {
    match setting.trim().to_ascii_lowercase().as_str() {
        "any" | "all" | "" => Ok(None),
        "auto" => Ok(geo::detect().await),
        code => {
            let code = code.to_ascii_uppercase();
            if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
                bail!("--country expects a two-letter code such as AU, or `auto`/`any`");
            }
            Ok(Some(geo::Home {
                country: code,
                source: "given",
            }))
        }
    }
}

/// The in-country list is a scan of the open internet, and some of it has gone
/// stale, so check which entries still answer before they take up slots. One
/// query each, in parallel, on a short deadline; survivors come back in
/// ascending round-trip time, which puts the nearest ones first.
async fn screen_candidates(entries: Vec<Entry>, shared: &Shared) -> Vec<Entry> {
    if entries.is_empty() {
        return entries;
    }
    let mut tasks = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let (server, shared) = (entry.server.clone(), shared.clone());
        tasks.push(tokio::spawn(async move {
            let Ok(mut client) = Client::new(&server, shared).await else {
                return (i, None);
            };
            let id = plan::query_id();
            let Ok(wire) = dns::encode_query(id, "example.com", 1, None) else {
                return (i, None);
            };
            let rtt = client
                .probe(&wire, id)
                .await
                .ok()
                .map(|r| r.elapsed.as_secs_f64());
            (i, rtt)
        }));
    }

    let mut alive: Vec<(usize, f64)> = Vec::new();
    for task in tasks {
        if let Ok((i, Some(rtt))) = task.await {
            alive.push((i, rtt));
        }
    }
    alive.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut entries: Vec<Option<Entry>> = entries.into_iter().map(Some).collect();
    alive
        .into_iter()
        .filter_map(|(i, _)| entries[i].take())
        .collect()
}

/// Trim the selection to `max` entries while keeping room for regional
/// resolvers, which would otherwise be crowded out entirely: the global
/// providers all sort ahead of them. Entries stay in their existing order, and
/// pinned ones are never dropped.
fn apply_budget(entries: Vec<Entry>, max: usize, regional_slots: usize) -> Vec<Entry> {
    if max == 0 || entries.len() <= max {
        return entries;
    }
    let mut chosen = vec![false; entries.len()];
    let mut total = 0;
    for (i, e) in entries.iter().enumerate() {
        if e.pinned {
            chosen[i] = true;
            total += 1;
        }
    }

    let room = max.saturating_sub(total);
    let regional_target = regional_slots.min(room);
    let general_target = room - regional_target;

    let fill = |want: usize, regional: bool, chosen: &mut Vec<bool>, total: &mut usize| {
        let mut taken = 0;
        for (i, e) in entries.iter().enumerate() {
            if taken >= want {
                break;
            }
            if !chosen[i] && (e.section == Section::Regional) == regional {
                chosen[i] = true;
                taken += 1;
                *total += 1;
            }
        }
    };
    fill(general_target, false, &mut chosen, &mut total);
    fill(regional_target, true, &mut chosen, &mut total);

    // If one side ran out, hand its unused slots back to the other.
    if total < max {
        for slot in chosen.iter_mut() {
            if total >= max {
                break;
            }
            if !*slot {
                *slot = true;
                total += 1;
            }
        }
    }

    entries
        .into_iter()
        .zip(chosen)
        .filter_map(|(e, keep)| keep.then_some(e))
        .collect()
}

/// Wrap a resolver the user named into a catalogue entry that skips filtering
/// and truncation.
fn pin(server: Server) -> Entry {
    Entry {
        section: Section::Anycast,
        provider: server.name.clone(),
        variant: String::new(),
        filtering: Filtering::Default,
        country: None,
        ipv6: server.target.starts_with('['),
        pinned: true,
        server,
    }
}

/// The resolvers this machine already uses — the baseline worth beating.
fn system_resolvers() -> Vec<Entry> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(addr) = line.trim().strip_prefix("nameserver ") else {
            continue;
        };
        let addr = addr.trim();
        let ipv6 = addr.contains(':');
        let spec = if ipv6 {
            format!("udp://[{addr}]")
        } else {
            format!("udp://{addr}")
        };
        if let Ok(mut server) = Server::parse(&spec) {
            server.name = format!("System ({addr})");
            out.push(Entry {
                provider: format!("system:{addr}"),
                ipv6,
                ..pin(server)
            });
        }
    }
    out
}

/// Does this host have a route to the IPv6 internet? A UDP `connect` performs
/// the route lookup without putting a packet on the wire.
async fn probe_ipv6() -> bool {
    let Ok(sock) = tokio::net::UdpSocket::bind("[::]:0").await else {
        return false;
    };
    sock.connect("[2001:4860:4860::8888]:53").await.is_ok()
}

#[allow(clippy::too_many_arguments)]
async fn bench_server(
    row: usize,
    server: &Server,
    jobs: Arc<Vec<Job>>,
    cfg: Arc<Config>,
    shared: Shared,
    cancel: watch::Receiver<bool>,
    state: live::Handle,
    ecs_probe: Option<Arc<ecs::EcsProbe>>,
) {
    let total = jobs.len();
    state.lock().unwrap().start(row);

    // Probe once before committing to the full run: a resolver that can't be
    // reached at all shouldn't take `total × timeout` to find that out. The
    // probe also warms the connection so setup isn't charged to a timed query.
    let mut probe = match Client::new(server, shared.clone()).await {
        Ok(c) => c,
        Err(e) => {
            let mut live = state.lock().unwrap();
            live.unreachable(row, format!("{e:#}"));
            live.skip(total);
            live.finish(row);
            return;
        }
    };
    let mut last_err = None;
    let mut alive = false;
    let mut probe_cancel = cancel.clone();
    for _ in 0..2 {
        let id = plan::query_id();
        let Ok(wire) = dns::encode_query(id, &jobs[0].qname, cfg.qtype, None) else {
            break;
        };
        let outcome = tokio::select! {
            biased;
            _ = probe_cancel.wait_for(|c| *c) => break,
            r = probe.probe(&wire, id) => r,
        };
        match outcome {
            Ok(_) => {
                alive = true;
                break;
            }
            Err(e) => last_err = Some(format!("{e:#}")),
        }
    }
    if !alive {
        let mut live = state.lock().unwrap();
        if !*cancel.borrow() {
            live.unreachable(row, last_err.unwrap_or_else(|| "no response".to_string()));
        }
        live.skip(total);
        live.finish(row);
        return;
    }

    // The client-subnet and edge checks reuse the warm probe connection.
    if let Some(probe_cfg) = &ecs_probe
        && !*cancel.borrow()
    {
        let report = ecs::probe(&mut probe, probe_cfg).await;
        state.lock().unwrap().set_ecs(row, report);
    }
    drop(probe);

    let next = Arc::new(AtomicUsize::new(0));
    let workers = cfg.concurrency.min(total.max(1));
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (server, jobs, cfg, shared, mut cancel, state, next) = (
            server.clone(),
            jobs.clone(),
            cfg.clone(),
            shared.clone(),
            cancel.clone(),
            state.clone(),
            next.clone(),
        );

        handles.push(tokio::spawn(async move {
            let mut client = match Client::new(&server, shared).await {
                Ok(c) => c,
                Err(e) => {
                    state
                        .lock()
                        .unwrap()
                        .error(row, short_error(&format!("{e:#}")));
                    return;
                }
            };
            // Establish this worker's own connection outside the timed section.
            let _ = client.connect().await;

            loop {
                if *cancel.borrow() {
                    break;
                }
                let idx = next.fetch_add(1, Ordering::Relaxed);
                let Some(job) = jobs.get(idx) else { break };

                let id = plan::query_id();
                let Ok(wire) = dns::encode_query(id, &job.qname, cfg.qtype, None) else {
                    state
                        .lock()
                        .unwrap()
                        .error(row, "bad domain name".to_string());
                    continue;
                };
                // Abandon an in-flight query the moment Ctrl-C lands, rather
                // than waiting out its timeout.
                let outcome = tokio::select! {
                    biased;
                    _ = cancel.wait_for(|c| *c) => break,
                    r = client.query(&wire, id) => r,
                };
                let mut live = state.lock().unwrap();
                match outcome {
                    Ok(r) => live.sample(
                        row,
                        idx,
                        r.elapsed.as_secs_f64() * 1000.0,
                        r.rcode,
                        r.rcode == 0 && r.answers > 0,
                    ),
                    Err(e) => live.error(row, short_error(&format!("{e:#}"))),
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let mut live = state.lock().unwrap();
    // Queries the run never got to still have to leave the progress total.
    let issued = next.load(Ordering::Relaxed).min(total);
    live.skip(total.saturating_sub(issued));
    live.finish(row);
}

/// Collapse error text so the breakdown groups failures instead of listing them.
fn short_error(msg: &str) -> String {
    let lower = msg.to_lowercase();
    for (needle, label) in [
        ("timed out", "timeout"),
        ("certificate", "TLS certificate error"),
        ("handshake", "TLS handshake failed"),
        ("connection refused", "connection refused"),
        ("connection reset", "connection reset"),
        ("unreachable", "network unreachable"),
        ("resolving", "endpoint DNS lookup failed"),
        ("connection closed", "connection closed early"),
        ("id mismatch", "response ID mismatch"),
    ] {
        if lower.contains(needle) {
            return label.to_string();
        }
    }
    msg.split(':').next().unwrap_or(msg).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_grouped() {
        assert_eq!(short_error("timed out after 2000ms"), "timeout");
        assert_eq!(
            short_error("TLS handshake failed: bad record"),
            "TLS handshake failed"
        );
    }

    #[test]
    fn bare_ipv6_specs_need_no_brackets() {
        for spec in [
            "2606:4700:4700::1111",
            "udp://2001:4860:4860::8888",
            "tls://2606:4700:4700::1111#one.one.one.one",
        ] {
            let s = Server::parse(spec).unwrap_or_else(|e| panic!("{spec}: {e:#}"));
            assert!(
                s.target.starts_with('['),
                "{spec} produced target {}",
                s.target
            );
        }
        // Brackets stay available for the ambiguous host:port case.
        let s = Server::parse("[2606:4700:4700::1111]:5353").unwrap();
        assert_eq!(s.target, "[2606:4700:4700::1111]:5353");
    }

    fn entry(name: &str, section: Section, pinned: bool) -> Entry {
        Entry {
            section,
            ..pin(Server::parse(&format!("{name} = udp://127.0.0.1")).unwrap())
        }
        .tap(|e| e.pinned = pinned)
    }

    trait Tap: Sized {
        fn tap(mut self, f: impl FnOnce(&mut Self)) -> Self {
            f(&mut self);
            self
        }
    }
    impl Tap for Entry {}

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.provider.as_str()).collect()
    }

    #[test]
    fn budget_reserves_slots_for_regional_resolvers() {
        // Global providers all sort first, so without a reserved slice the
        // regional ones would never make the cut.
        let mut entries: Vec<Entry> = (0..8)
            .map(|i| entry(&format!("global{i}"), Section::Anycast, false))
            .collect();
        entries.extend((0..8).map(|i| entry(&format!("regional{i}"), Section::Regional, false)));

        let kept = apply_budget(entries, 6, 2);
        assert_eq!(
            names(&kept),
            vec![
                "global0",
                "global1",
                "global2",
                "global3",
                "regional0",
                "regional1"
            ]
        );
    }

    #[test]
    fn budget_hands_unused_slots_back() {
        // Only one regional entry exists, so the other reserved slot should go
        // to a global provider rather than being wasted.
        let mut entries: Vec<Entry> = (0..8)
            .map(|i| entry(&format!("global{i}"), Section::Anycast, false))
            .collect();
        entries.push(entry("regional0", Section::Regional, false));

        let kept = apply_budget(entries, 4, 3);
        assert_eq!(kept.len(), 4);
        assert!(names(&kept).contains(&"regional0"));
        assert_eq!(
            names(&kept).iter().filter(|n| n.starts_with("g")).count(),
            3
        );
    }

    #[test]
    fn budget_never_drops_pinned_entries() {
        let mut entries: Vec<Entry> = (0..10)
            .map(|i| entry(&format!("global{i}"), Section::Anycast, false))
            .collect();
        entries.push(entry("mine", Section::Anycast, true));

        let kept = apply_budget(entries, 3, 1);
        assert!(names(&kept).contains(&"mine"));
        assert_eq!(kept.len(), 3);
    }

    #[test]
    fn budget_of_zero_keeps_everything() {
        let entries: Vec<Entry> = (0..5)
            .map(|i| entry(&format!("g{i}"), Section::Anycast, false))
            .collect();
        assert_eq!(apply_budget(entries, 0, 2).len(), 5);
    }

    #[test]
    fn pinned_entries_keep_their_name() {
        let e = pin(Server::parse("Pi-hole = udp://10.0.0.53").unwrap());
        assert!(e.pinned);
        assert_eq!(e.provider, "Pi-hole");
        assert!(!e.ipv6);
    }
}
