//! The results model and how it is rendered: terminal table, legend, JSON, CSV.
//!
//! `render_table` returns lines rather than printing them, so the live view and
//! the final output are the same code drawing the same rows.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::Path;

use crate::ecs::EcsReport;
use crate::plan::Pool;
use crate::server::Server;
use crate::stats::Stats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Running,
    Done,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolStats {
    pub queries: usize,
    pub succeeded: usize,
    #[serde(flatten)]
    pub stats: Option<Stats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerReport {
    pub name: String,
    pub protocol: String,
    pub endpoint: String,
    pub queries: usize,
    pub succeeded: usize,
    pub failed: usize,
    /// Successful responses whose rcode was NOERROR *and* carried an answer.
    pub resolved: usize,
    pub overall: Option<Stats>,
    pub pools: BTreeMap<String, PoolStats>,
    pub rcodes: BTreeMap<String, usize>,
    pub errors: BTreeMap<String, usize>,
    pub unreachable: Option<String>,
    pub ecs: Option<EcsReport>,
    #[serde(skip)]
    pub status: Status,
}

impl ServerReport {
    pub fn blank(server: &Server) -> ServerReport {
        ServerReport {
            name: server.name.clone(),
            protocol: server.proto.label().to_string(),
            endpoint: server.endpoint(),
            queries: 0,
            succeeded: 0,
            failed: 0,
            resolved: 0,
            overall: None,
            pools: BTreeMap::new(),
            rcodes: BTreeMap::new(),
            errors: BTreeMap::new(),
            unreachable: None,
            ecs: None,
            status: Status::Pending,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.queries == 0 {
            0.0
        } else {
            self.succeeded as f64 / self.queries as f64 * 100.0
        }
    }

    fn pool(&self, pool: Pool) -> Option<&Stats> {
        self.pools.get(pool.key())?.stats.as_ref()
    }

    /// How much slower the long tail is than the popular head — the part of a
    /// resolver's speed that isn't just a cache hit. Taken from the averages,
    /// so it's the gap between the two columns next to it.
    fn tail_delta(&self) -> Option<f64> {
        let popular = self.pool(Pool::Popular)?;
        let random = self.pool(Pool::Random)?;
        Some(random.avg - popular.avg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Avg,
    Median,
    P95,
    Min,
    Max,
    Success,
    Popular,
    Random,
    Tail,
}

impl SortKey {
    pub fn parse(s: &str) -> Result<SortKey> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "avg" | "mean" => SortKey::Avg,
            "median" | "med" | "p50" => SortKey::Median,
            "p95" => SortKey::P95,
            "min" | "best" => SortKey::Min,
            "max" | "worst" => SortKey::Max,
            "success" | "loss" | "reliability" => SortKey::Success,
            "popular" | "pop" => SortKey::Popular,
            "random" | "rnd" | "tail" => SortKey::Random,
            "delta" | "tail-delta" => SortKey::Tail,
            other => anyhow::bail!(
                "unknown sort key '{other}' (avg, median, p95, min, max, success, popular, random, delta)"
            ),
        })
    }

    fn value(self, r: &ServerReport) -> f64 {
        let overall = |f: fn(&Stats) -> f64| r.overall.as_ref().map(f).unwrap_or(f64::INFINITY);
        match self {
            SortKey::Success => {
                if r.queries == 0 {
                    f64::INFINITY
                } else {
                    -r.success_rate()
                }
            }
            SortKey::Avg => overall(|s| s.avg),
            SortKey::Median => overall(|s| s.median),
            SortKey::P95 => overall(|s| s.p95),
            SortKey::Min => overall(|s| s.min),
            SortKey::Max => overall(|s| s.max),
            SortKey::Popular => r
                .pool(Pool::Popular)
                .map(|s| s.avg)
                .unwrap_or(f64::INFINITY),
            SortKey::Random => r.pool(Pool::Random).map(|s| s.avg).unwrap_or(f64::INFINITY),
            SortKey::Tail => r.tail_delta().unwrap_or(f64::INFINITY),
        }
    }
}

pub fn sort(reports: &mut [ServerReport], key: SortKey) {
    reports.sort_by(|a, b| {
        key.value(a)
            .partial_cmp(&key.value(b))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
}

// ---------------------------------------------------------------- rendering

pub struct Paint {
    on: bool,
}

impl Paint {
    pub fn new() -> Paint {
        Paint {
            on: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }
    #[cfg(test)]
    pub fn plain() -> Paint {
        Paint { on: false }
    }
    fn wrap(&self, code: &str, text: &str) -> String {
        if self.on && !text.is_empty() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn dim(&self, t: &str) -> String {
        self.wrap("2", t)
    }
    fn bold(&self, t: &str) -> String {
        self.wrap("1", t)
    }
    fn green(&self, t: &str) -> String {
        self.wrap("32", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.wrap("33", t)
    }
    fn red(&self, t: &str) -> String {
        self.wrap("31", t)
    }
    fn cyan(&self, t: &str) -> String {
        self.wrap("36", t)
    }
}

pub struct TableOpts<'a> {
    pub pools: &'a [Pool],
    pub verbose: bool,
    pub ecs: bool,
    /// Terminal width; columns are dropped to fit.
    pub width: usize,
    /// Cap on printed rows, for a live view taller than the terminal.
    pub max_rows: Option<usize>,
    pub paint: &'a Paint,
}

fn ms(v: f64) -> String {
    if !v.is_finite() {
        "-".to_string()
    } else if v.abs() >= 100.0 {
        format!("{v:.0}")
    } else if v.abs() >= 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    }
}

fn signed_ms(v: f64) -> String {
    if !v.is_finite() {
        "-".to_string()
    } else if v > 0.0 {
        format!("+{}", ms(v))
    } else {
        ms(v)
    }
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Pad accounting for the fact that colour codes have no width.
fn pad(text: &str, visible: usize, width: usize, right: bool) -> String {
    let fill = " ".repeat(width.saturating_sub(visible));
    if right {
        format!("{fill}{text}")
    } else {
        format!("{text}{fill}")
    }
}

const NUM: usize = 9;
const PROTO_W: usize = 9;

/// Which columns survive the terminal's width.
pub struct Layout {
    name_w: usize,
    /// 2 = avg and p95 per pool, 1 = avg only.
    per_pool_cols: usize,
    show_delta: bool,
}

impl Layout {
    pub fn shows_p95(&self) -> bool {
        self.per_pool_cols == 2
    }
    pub fn shows_delta(&self) -> bool {
        self.show_delta
    }
}

/// Drop detail columns on a narrow terminal rather than wrapping rows.
pub fn layout(reports: &[ServerReport], opts: &TableOpts) -> Layout {
    let name_w = reports
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(20)
        .clamp(6, 34);
    let fixed = 4 + name_w + 2 + PROTO_W + 7 + if opts.ecs { 6 + NUM } else { 0 };
    let per_pool_cols = if fixed + opts.pools.len() * NUM * 2 + NUM <= opts.width {
        2
    } else {
        1
    };
    let show_delta =
        opts.pools.len() > 1 && fixed + opts.pools.len() * NUM * per_pool_cols + NUM <= opts.width;
    Layout {
        name_w,
        per_pool_cols,
        show_delta,
    }
}

/// The width to render at when output isn't going to a terminal.
pub fn terminal_width() -> usize {
    let term = console::Term::stdout();
    if term.is_term() {
        (term.size().1 as usize).clamp(60, 200)
    } else {
        120
    }
}

/// Render the ranking. Returns lines so the live view can redraw them in place.
pub fn render_table(reports: &[ServerReport], opts: &TableOpts) -> Vec<String> {
    let p = opts.paint;
    let Layout {
        name_w,
        per_pool_cols,
        show_delta,
    } = layout(reports, opts);

    let mut header = String::new();
    header.push_str(&pad("#", 1, 3, true));
    header.push_str("  ");
    header.push_str(&pad("SERVER", 6, name_w, false));
    header.push_str("  ");
    header.push_str(&pad("PROTO", 5, PROTO_W, false));
    for pool in opts.pools {
        let tag = match pool {
            Pool::Popular => "POP",
            Pool::Random => "RND",
        };
        header.push_str(&pad(&format!("{tag}-AVG"), tag.len() + 4, NUM, true));
        if per_pool_cols == 2 {
            header.push_str(&pad(&format!("{tag}-P95"), tag.len() + 4, NUM, true));
        }
    }
    if show_delta {
        header.push_str(&pad("TAIL-Δ", 6, NUM, true));
    }
    header.push_str(&pad("OK", 2, 7, true));
    if opts.ecs {
        header.push_str(&pad("ECS", 3, 6, true));
        header.push_str(&pad("EDGE", 4, NUM, true));
    }

    let mut lines = vec![p.bold(&header)];
    let shown = opts.max_rows.unwrap_or(reports.len()).min(reports.len());

    for (i, r) in reports.iter().take(shown).enumerate() {
        let mut line = String::new();
        let pending = r.status == Status::Pending;
        let rank = if r.status == Status::Running {
            "»".to_string()
        } else if pending {
            String::new()
        } else {
            format!("{}.", i + 1)
        };
        line.push_str(&pad(&p.dim(&rank), rank.chars().count(), 3, true));
        line.push_str("  ");

        let name = truncate(&r.name, name_w);
        let name_len = name.chars().count();
        let painted = if pending {
            p.dim(&name)
        } else if i == 0 && r.status == Status::Done && r.overall.is_some() {
            p.green(&name)
        } else {
            p.bold(&name)
        };
        line.push_str(&pad(&painted, name_len, name_w, false));
        line.push_str("  ");
        line.push_str(&pad(
            &p.dim(&r.protocol),
            r.protocol.chars().count(),
            PROTO_W,
            false,
        ));

        // A resolver with nothing to show yet, or nothing to show at all.
        if r.overall.is_none() {
            let note = match (&r.unreachable, pending) {
                (Some(reason), _) => p.red(&format!("failed — {}", truncate(reason, 56))),
                (None, true) => p.dim("waiting"),
                (None, false) => p.dim("no answers yet"),
            };
            line.push_str(&note);
            lines.push(line);
            if opts.verbose {
                lines.extend(detail_lines(r, p));
            }
            continue;
        }

        for pool in opts.pools {
            match r.pool(*pool) {
                Some(s) => {
                    let avg = ms(s.avg);
                    line.push_str(&pad(&avg, avg.len(), NUM, true));
                    if per_pool_cols == 2 {
                        let v = ms(s.p95);
                        line.push_str(&pad(&p.dim(&v), v.len(), NUM, true));
                    }
                }
                None => {
                    line.push_str(&pad(&p.dim("-"), 1, NUM, true));
                    if per_pool_cols == 2 {
                        line.push_str(&pad(&p.dim("-"), 1, NUM, true));
                    }
                }
            }
        }

        if show_delta {
            match r.tail_delta() {
                Some(d) => {
                    let text = signed_ms(d);
                    // A big gap means the resolver leans on its cache.
                    let painted = if d <= 10.0 {
                        p.green(&text)
                    } else if d <= 50.0 {
                        text.clone()
                    } else {
                        p.yellow(&text)
                    };
                    line.push_str(&pad(&painted, text.len(), NUM, true));
                }
                None => line.push_str(&pad(&p.dim("-"), 1, NUM, true)),
            }
        }

        let rate = r.success_rate();
        let ok = format!("{rate:.0}%");
        let painted = if rate >= 99.5 {
            p.green(&ok)
        } else if rate >= 95.0 {
            p.yellow(&ok)
        } else {
            p.red(&ok)
        };
        line.push_str(&pad(&painted, ok.len(), 7, true));

        if opts.ecs {
            match &r.ecs {
                Some(e) => {
                    let label = e.support.label();
                    let painted = match e.support {
                        crate::ecs::Support::Echoed | crate::ecs::Support::Differs => p.cyan(label),
                        _ => p.dim(label),
                    };
                    line.push_str(&pad(&painted, label.len(), 6, true));
                    match e.edge_rtt_ms {
                        Some(v) => {
                            let text = ms(v);
                            line.push_str(&pad(&text, text.len(), NUM, true));
                        }
                        None => line.push_str(&pad(&p.dim("-"), 1, NUM, true)),
                    }
                }
                None => {
                    line.push_str(&pad(&p.dim("-"), 1, 6, true));
                    line.push_str(&pad(&p.dim("-"), 1, NUM, true));
                }
            }
        }

        lines.push(line);
        if opts.verbose {
            lines.extend(detail_lines(r, p));
        }
    }

    if shown < reports.len() {
        lines.push(p.dim(&format!("     … {} more", reports.len() - shown)));
    }
    lines
}

fn detail_lines(r: &ServerReport, p: &Paint) -> Vec<String> {
    let mut out = vec![format!("      {}", p.dim(&r.endpoint))];
    let mut notes: Vec<String> = r
        .rcodes
        .iter()
        .filter(|(code, _)| code.as_str() != "NOERROR")
        .map(|(code, n)| format!("{code} ×{n}"))
        .collect();
    notes.extend(r.errors.iter().map(|(e, n)| format!("{e} ×{n}")));
    if let Some(e) = &r.ecs
        && !e.addresses.is_empty()
    {
        notes.push(format!("edge {}", e.addresses.join(", ")));
    }
    if !notes.is_empty() {
        out.push(format!("      {}", p.dim(&notes.join(", "))));
    }
    out
}

/// The short "what am I looking at" block printed under the final table. Only
/// explains the columns that actually made it onto the screen.
pub fn legend(reports: &[ServerReport], opts: &TableOpts) -> Vec<String> {
    let p = opts.paint;
    let layout = layout(reports, opts);
    let two = opts.pools.len() > 1;
    let ecs = opts.ecs;
    let mut out = vec![p.bold("how to read this")];
    let mut row = |k: &str, v: &str| out.push(format!("  {}  {}", p.cyan(&format!("{k:<8}")), v));

    if two {
        row(
            "POP-AVG",
            "average on popular domains — nearly always cache hits, so this is your everyday latency",
        );
        row(
            "RND-AVG",
            "average on randomly sampled long-tail domains — mostly cache misses, the resolver's real work",
        );
        if layout.shows_delta() {
            row(
                "TAIL-Δ",
                "RND-AVG minus POP-AVG. Small = deep cache or fast recursion. Large = it only looks fast on popular sites",
            );
        }
    } else {
        row("AVG", "average query latency");
    }
    if layout.shows_p95() {
        row(
            "P95",
            "the slow 1-in-20 query — watch this if browsing feels occasionally stuck rather than uniformly slow",
        );
    }
    row(
        "OK",
        "share of queries answered at all; every miss costs a client retry, typically ~1s",
    );
    if ecs {
        row(
            "ECS",
            "honours EDNS Client Subnet (yes* = answers change per subnet but no scope is echoed)",
        );
        row(
            "EDGE",
            "median TCP handshake to the CDN addresses this resolver returned — lower means a closer edge",
        );
    }
    out.push(String::new());
    let watch = if layout.shows_p95() { "and P95 " } else { "" };
    out.push(p.dim(&if two {
        format!(
            "pick on: low RND-AVG {watch}at 100% OK. A low POP-AVG on its own only means popular sites are cached."
        )
    } else {
        format!("pick on: low AVG {watch}at 100% OK.")
    }));
    if ecs {
        out.push(p.dim(
            "ECS trades DNS speed for a closer CDN edge: compare EDGE across resolvers, not their DNS times.",
        ));
    }
    out
}

/// Latency is averaged only over queries that came back, so a lossy resolver
/// can rank well on round trips it never had to pay for.
pub fn loss_warning(reports: &[ServerReport], p: &Paint) -> Option<String> {
    let lossy = reports
        .iter()
        .filter(|r| r.overall.is_some() && r.success_rate() < 95.0)
        .count();
    (lossy > 0).then(|| {
        p.yellow(&format!(
            "note: {lossy} resolver{} answered under 95% of queries — those times cover only the queries that succeeded",
            if lossy == 1 { "" } else { "s" }
        ))
    })
}

pub fn to_json(reports: &[ServerReport], meta: &serde_json::Value) -> Result<String> {
    let doc = serde_json::json!({ "run": meta, "results": reports });
    Ok(serde_json::to_string_pretty(&doc)?)
}

pub fn write_csv(path: &Path, reports: &[ServerReport], pools: &[Pool]) -> Result<()> {
    let mut header =
        String::from("rank,name,protocol,endpoint,queries,succeeded,resolved,success_pct");
    for pool in pools {
        let k = pool.key();
        header.push_str(&format!(
            ",{k}_queries,{k}_avg_ms,{k}_median_ms,{k}_p95_ms,{k}_min_ms,{k}_max_ms"
        ));
    }
    header.push_str(",overall_avg_ms,overall_median_ms,overall_p95_ms,tail_delta_ms");
    header.push_str(",ecs_support,ecs_scope,edge_rtt_ms\n");

    let num = |v: Option<f64>| v.map(|v| format!("{v:.3}")).unwrap_or_default();
    let mut out = header;
    for (i, r) in reports.iter().enumerate() {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{:.2}",
            i + 1,
            csv_field(&r.name),
            r.protocol,
            csv_field(&r.endpoint),
            r.queries,
            r.succeeded,
            r.resolved,
            r.success_rate(),
        ));
        for pool in pools {
            let ps = r.pools.get(pool.key());
            let s = ps.and_then(|p| p.stats.as_ref());
            out.push_str(&format!(
                ",{},{},{},{},{},{}",
                ps.map(|p| p.queries).unwrap_or(0),
                num(s.map(|s| s.avg)),
                num(s.map(|s| s.median)),
                num(s.map(|s| s.p95)),
                num(s.map(|s| s.min)),
                num(s.map(|s| s.max)),
            ));
        }
        out.push_str(&format!(
            ",{},{},{},{}",
            num(r.overall.as_ref().map(|s| s.avg)),
            num(r.overall.as_ref().map(|s| s.median)),
            num(r.overall.as_ref().map(|s| s.p95)),
            num(r.tail_delta()),
        ));
        out.push_str(&format!(
            ",{},{},{}\n",
            r.ecs.as_ref().map(|e| e.support.label()).unwrap_or(""),
            r.ecs
                .as_ref()
                .and_then(|e| e.scope)
                .map(|s| s.to_string())
                .unwrap_or_default(),
            num(r.ecs.as_ref().and_then(|e| e.edge_rtt_ms)),
        ));
    }
    std::fs::write(path, out).with_context(|| format!("writing {}", path.display()))
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(name: &str, pop: Option<f64>, rnd: Option<f64>) -> ServerReport {
        let mut pools = BTreeMap::new();
        for (pool, v) in [(Pool::Popular, pop), (Pool::Random, rnd)] {
            if let Some(v) = v {
                pools.insert(
                    pool.key().to_string(),
                    PoolStats {
                        queries: 5,
                        succeeded: 5,
                        stats: Stats::from_samples(&[v]),
                    },
                );
            }
        }
        let all: Vec<f64> = [pop, rnd].into_iter().flatten().collect();
        ServerReport {
            name: name.to_string(),
            protocol: "DoH".into(),
            endpoint: "https://example/dns-query".into(),
            queries: 10,
            succeeded: if all.is_empty() { 0 } else { 10 },
            failed: 0,
            resolved: 10,
            overall: Stats::from_samples(&all),
            pools,
            rcodes: BTreeMap::new(),
            errors: BTreeMap::new(),
            unreachable: None,
            ecs: None,
            status: Status::Done,
        }
    }

    #[test]
    fn sorts_failures_last() {
        let mut rs = vec![
            report("slow", Some(90.0), Some(120.0)),
            report("dead", None, None),
            report("fast", Some(10.0), Some(20.0)),
        ];
        sort(&mut rs, SortKey::Avg);
        let names: Vec<_> = rs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["fast", "slow", "dead"]);
    }

    #[test]
    fn sorts_by_pool() {
        let mut rs = vec![
            report("cache-only", Some(5.0), Some(300.0)),
            report("consistent", Some(30.0), Some(40.0)),
        ];
        sort(&mut rs, SortKey::Popular);
        assert_eq!(rs[0].name, "cache-only");
        sort(&mut rs, SortKey::Random);
        assert_eq!(rs[0].name, "consistent");
        sort(&mut rs, SortKey::Tail);
        assert_eq!(rs[0].name, "consistent");
    }

    #[test]
    fn tail_delta_is_random_minus_popular() {
        let r = report("x", Some(10.0), Some(85.0));
        assert_eq!(r.tail_delta(), Some(75.0));
    }

    #[test]
    fn table_has_a_row_per_report() {
        let rs = vec![
            report("a", Some(10.0), Some(20.0)),
            report("b", Some(11.0), Some(21.0)),
        ];
        let p = Paint::plain();
        let lines = render_table(
            &rs,
            &TableOpts {
                pools: &Pool::ALL,
                verbose: false,
                ecs: false,
                width: 120,
                max_rows: None,
                paint: &p,
            },
        );
        assert_eq!(lines.len(), 3); // header + two rows
        assert!(lines[0].contains("POP-AVG") && lines[0].contains("RND-AVG"));
        assert!(lines[1].contains(" a "));
    }

    #[test]
    fn narrow_terminals_drop_columns() {
        let rs = vec![report("a", Some(10.0), Some(20.0))];
        let p = Paint::plain();
        let lines = render_table(
            &rs,
            &TableOpts {
                pools: &Pool::ALL,
                verbose: false,
                ecs: false,
                width: 60,
                max_rows: None,
                paint: &p,
            },
        );
        assert!(!lines[0].contains("POP-P95"));
        assert!(lines[0].contains("POP-AVG"));
        assert!(lines.iter().all(|l| l.chars().count() <= 80));
    }

    #[test]
    fn max_rows_truncates_with_a_note() {
        let rs: Vec<_> = (0..10)
            .map(|i| report(&format!("s{i}"), Some(i as f64), Some(i as f64)))
            .collect();
        let p = Paint::plain();
        let lines = render_table(
            &rs,
            &TableOpts {
                pools: &Pool::ALL,
                verbose: false,
                ecs: false,
                width: 120,
                max_rows: Some(4),
                paint: &p,
            },
        );
        assert_eq!(lines.len(), 6); // header + 4 rows + "… 6 more"
        assert!(lines.last().unwrap().contains("6 more"));
    }

    #[test]
    fn csv_quotes_commas() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("ab"), "ab");
    }
}
