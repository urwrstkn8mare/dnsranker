//! The run's shared state, and the in-place terminal view of it.
//!
//! Workers write results here as they arrive; the renderer reads the same state
//! a few times a second and redraws the ranking, so the table you watch during
//! the run is the table you're left with at the end.

use console::Term;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns;
use crate::ecs::EcsReport;
use crate::plan::{Job, Pool};
use crate::report::{PoolStats, ServerReport, Status};
use crate::server::Server;
use crate::stats::Stats;

pub struct Row {
    server: Server,
    status: Status,
    /// (job index, milliseconds), in completion order.
    samples: Vec<(usize, f64)>,
    rcodes: BTreeMap<u8, usize>,
    errors: BTreeMap<String, usize>,
    attempted: usize,
    resolved: usize,
    unreachable: Option<String>,
    ecs: Option<EcsReport>,
}

pub struct Live {
    rows: Vec<Row>,
    jobs: Arc<Vec<Job>>,
    pub total: usize,
    pub completed: usize,
    pub finished_servers: usize,
    started: Instant,
}

pub type Handle = Arc<Mutex<Live>>;

impl Live {
    pub fn new(servers: &[Server], jobs: Arc<Vec<Job>>) -> Live {
        Live {
            rows: servers
                .iter()
                .map(|s| Row {
                    server: s.clone(),
                    status: Status::Pending,
                    samples: Vec::new(),
                    rcodes: BTreeMap::new(),
                    errors: BTreeMap::new(),
                    attempted: 0,
                    resolved: 0,
                    unreachable: None,
                    ecs: None,
                })
                .collect(),
            total: servers.len() * jobs.len(),
            completed: 0,
            finished_servers: 0,
            jobs,
            started: Instant::now(),
        }
    }

    pub fn start(&mut self, row: usize) {
        self.rows[row].status = Status::Running;
    }

    pub fn finish(&mut self, row: usize) {
        self.rows[row].status = Status::Done;
        self.finished_servers += 1;
    }

    pub fn sample(&mut self, row: usize, job: usize, ms: f64, rcode: u8, resolved: bool) {
        let r = &mut self.rows[row];
        r.samples.push((job, ms));
        *r.rcodes.entry(rcode).or_insert(0) += 1;
        r.attempted += 1;
        if resolved {
            r.resolved += 1;
        }
        self.completed += 1;
    }

    pub fn error(&mut self, row: usize, kind: String) {
        let r = &mut self.rows[row];
        *r.errors.entry(kind).or_insert(0) += 1;
        r.attempted += 1;
        self.completed += 1;
    }

    /// Queries skipped because the resolver was unreachable or the run was cut
    /// short still have to be accounted for in the progress total.
    pub fn skip(&mut self, count: usize) {
        self.completed += count;
    }

    pub fn unreachable(&mut self, row: usize, reason: String) {
        self.rows[row].unreachable = Some(reason);
    }

    pub fn set_ecs(&mut self, row: usize, ecs: EcsReport) {
        self.rows[row].ecs = Some(ecs);
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Snapshot every row as a report. `started_only` drops resolvers the run
    /// never got to, which is what an interrupted run wants.
    pub fn reports(&self, started_only: bool) -> Vec<ServerReport> {
        self.rows
            .iter()
            .filter(|r| {
                !started_only
                    || r.status != Status::Pending
                    || !r.samples.is_empty()
                    || r.unreachable.is_some()
            })
            .map(|r| self.report(r))
            .collect()
    }

    fn report(&self, r: &Row) -> ServerReport {
        let mut report = ServerReport::blank(&r.server);
        report.status = r.status;
        report.unreachable = r.unreachable.clone();
        report.queries = r.attempted;
        report.succeeded = r.samples.len();
        report.failed = r.attempted.saturating_sub(r.samples.len());
        report.resolved = r.resolved;
        report.ecs = r.ecs.clone();
        report.errors = r.errors.clone();
        report.rcodes = r
            .rcodes
            .iter()
            .map(|(k, v)| (dns::rcode_name(*k).to_string(), *v))
            .collect();

        // Order samples by job index so jitter reflects consecutive queries,
        // then split them by the pool their job came from.
        let mut ordered = r.samples.clone();
        ordered.sort_by_key(|(idx, _)| *idx);

        let mut by_pool: BTreeMap<Pool, Vec<f64>> = BTreeMap::new();
        let mut all = Vec::with_capacity(ordered.len());
        for (idx, ms) in &ordered {
            all.push(*ms);
            if let Some(job) = self.jobs.get(*idx) {
                by_pool.entry(job.pool).or_default().push(*ms);
            }
        }
        report.overall = Stats::from_samples(&all);

        // Attempt counts per pool, so a pool's OK rate is its own.
        let mut attempted: BTreeMap<Pool, usize> = BTreeMap::new();
        for job in self.jobs.iter().take(r.attempted) {
            *attempted.entry(job.pool).or_default() += 1;
        }
        for (pool, samples) in by_pool {
            report.pools.insert(
                pool.key().to_string(),
                PoolStats {
                    queries: *attempted.get(&pool).unwrap_or(&samples.len()),
                    succeeded: samples.len(),
                    stats: Stats::from_samples(&samples),
                },
            );
        }
        report
    }
}

/// Redraws a block of lines in place. Falls back to doing nothing at all when
/// stderr isn't a terminal, so piped output stays clean.
pub struct Screen {
    term: Term,
    enabled: bool,
    drawn: usize,
}

impl Screen {
    pub fn new(enabled: bool) -> Screen {
        let term = Term::stderr();
        Screen {
            enabled: enabled && term.is_term(),
            term,
            drawn: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Rows that fit on screen, leaving room for the header and status line.
    pub fn budget(&self) -> usize {
        let (rows, _) = self.term.size();
        (rows as usize).saturating_sub(4).max(3)
    }

    pub fn width(&self) -> usize {
        let (_, cols) = self.term.size();
        (cols as usize).clamp(60, 200)
    }

    pub fn draw(&mut self, lines: &[String]) {
        if !self.enabled {
            return;
        }
        // Never draw more than fits: clear_last_lines can only reach what is
        // still on screen, and an over-long frame would scroll away from it.
        let room = self.budget() + 2;
        let lines = &lines[..lines.len().min(room)];
        let _ = self.term.clear_last_lines(self.drawn);
        for line in lines {
            let _ = self.term.write_line(line);
        }
        self.drawn = lines.len();
    }

    /// Wipe the live frame, leaving the terminal where it was before the run.
    pub fn clear(&mut self) {
        if self.enabled && self.drawn > 0 {
            let _ = self.term.clear_last_lines(self.drawn);
            self.drawn = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Pool;
    use crate::server::Server;

    fn jobs() -> Arc<Vec<Job>> {
        Arc::new(vec![
            Job {
                qname: "a.example".into(),
                pool: Pool::Popular,
            },
            Job {
                qname: "b.example".into(),
                pool: Pool::Random,
            },
            Job {
                qname: "c.example".into(),
                pool: Pool::Popular,
            },
            Job {
                qname: "d.example".into(),
                pool: Pool::Random,
            },
        ])
    }

    #[test]
    fn splits_samples_by_pool() {
        let servers = vec![Server::parse("1.1.1.1").unwrap()];
        let mut live = Live::new(&servers, jobs());
        live.start(0);
        live.sample(0, 0, 10.0, 0, true);
        live.sample(0, 1, 100.0, 0, true);
        live.sample(0, 2, 20.0, 0, true);
        live.sample(0, 3, 200.0, 0, true);
        live.finish(0);

        let reports = live.reports(false);
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!(r.succeeded, 4);
        assert_eq!(r.pools["popular"].stats.as_ref().unwrap().avg, 15.0);
        assert_eq!(r.pools["random"].stats.as_ref().unwrap().avg, 150.0);
        assert_eq!(r.overall.as_ref().unwrap().avg, 82.5);
    }

    #[test]
    fn errors_count_against_the_success_rate() {
        let servers = vec![Server::parse("1.1.1.1").unwrap()];
        let mut live = Live::new(&servers, jobs());
        live.sample(0, 0, 10.0, 0, true);
        live.error(0, "timeout".into());
        let r = &live.reports(false)[0];
        assert_eq!(r.queries, 2);
        assert_eq!(r.succeeded, 1);
        assert_eq!(r.failed, 1);
        assert_eq!(r.success_rate(), 50.0);
    }

    #[test]
    fn started_only_drops_untouched_rows() {
        let servers = vec![
            Server::parse("1.1.1.1").unwrap(),
            Server::parse("8.8.8.8").unwrap(),
        ];
        let mut live = Live::new(&servers, jobs());
        live.start(0);
        live.sample(0, 0, 1.0, 0, true);
        assert_eq!(live.reports(false).len(), 2);
        assert_eq!(live.reports(true).len(), 1);
    }
}
