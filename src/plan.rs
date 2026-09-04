//! What gets queried: the domain pools and the resulting list of jobs.

use anyhow::{Result, bail};
use serde::Serialize;

/// Which sample of the web a query came from. Popular domains are the ones a
/// resolver is most likely to have cached; the random pool is drawn from the
/// long tail, where it has to do more of the work itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Pool {
    Popular,
    Random,
}

impl Pool {
    /// Both pools, in display order. Handy in tests and callers that
    /// want the default set.
    #[cfg(test)]
    pub const ALL: [Pool; 2] = [Pool::Popular, Pool::Random];
    pub fn key(self) -> &'static str {
        match self {
            Pool::Popular => "popular",
            Pool::Random => "random",
        }
    }

    pub fn parse(s: &str) -> Result<Pool> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "popular" | "top" | "head" => Pool::Popular,
            "random" | "tail" | "rand" => Pool::Random,
            other => bail!("unknown pool '{other}' (use popular or random)"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub qname: String,
    pub pool: Pool,
}

/// Build the query plan from the two already-selected pools. Pools are
/// interleaved so both progress together: partial results stay comparable, and
/// a network hiccup lands on both rather than skewing one.
pub fn build(
    popular: &[String],
    random: &[String],
    runs: usize,
    uncached: bool,
    rng: &mut Rng,
) -> Vec<Job> {
    let width = popular.len().max(random.len());
    let mut jobs = Vec::with_capacity((popular.len() + random.len()) * runs);
    for run in 0..runs {
        for i in 0..width {
            for (pool, source) in [(Pool::Popular, popular), (Pool::Random, random)] {
                let Some(domain) = source.get(i) else {
                    continue;
                };
                let qname = if uncached {
                    // A label no resolver can have cached, so the query costs a
                    // full recursion. NXDOMAIN is the expected (and timed) answer.
                    format!("dr{:x}{run:x}.{domain}", rng.next())
                } else {
                    domain.clone()
                };
                jobs.push(Job { qname, pool });
            }
        }
    }
    jobs
}

/// Small xorshift PRNG. Sampling and query IDs don't need anything stronger,
/// and an explicit seed makes two runs comparable.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(if seed == 0 { random_seed() } else { seed })
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

pub fn random_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    (nanos ^ 0x9e37_79b9_7f4a_7c15) | 1
}

/// Query IDs. Kept separate from the seeded planning RNG so that a fixed
/// `--seed` still produces unpredictable IDs on the wire.
pub fn query_id() -> u16 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0) };
    }
    STATE.with(|s| {
        let mut x = s.get();
        if x == 0 {
            // Mix in the address of the thread-local so workers starting in the
            // same nanosecond still diverge.
            x = random_seed() ^ (s as *const _ as u64).rotate_left(32);
            x |= 1;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        (x >> 16) as u16
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("d{i}.example")).collect()
    }

    #[test]
    fn interleaves_the_pools() {
        let pop = domains(3);
        let rnd: Vec<String> = (0..3).map(|i| format!("t{i}.example")).collect();
        let jobs = build(&pop, &rnd, 1, false, &mut Rng::new(42));
        assert_eq!(jobs.len(), 6);
        let pools: Vec<Pool> = jobs.iter().map(|j| j.pool).collect();
        assert_eq!(pools, [Pool::Popular, Pool::Random].repeat(3));
        assert_eq!(jobs[0].qname, "d0.example");
        assert_eq!(jobs[1].qname, "t0.example");
    }

    #[test]
    fn uneven_pools_still_work() {
        let jobs = build(&domains(5), &[], 1, false, &mut Rng::new(1));
        assert_eq!(jobs.len(), 5);
        assert!(jobs.iter().all(|j| j.pool == Pool::Popular));
    }

    #[test]
    fn runs_repeat_the_whole_plan() {
        let jobs = build(&domains(2), &domains(2), 3, false, &mut Rng::new(1));
        assert_eq!(jobs.len(), 12);
    }

    #[test]
    fn uncached_jobs_get_unique_labels() {
        let jobs = build(&domains(4), &[], 2, true, &mut Rng::new(5));
        assert_eq!(jobs.len(), 8);
        let unique: std::collections::HashSet<&str> =
            jobs.iter().map(|j| j.qname.as_str()).collect();
        assert_eq!(unique.len(), 8);
        assert!(jobs.iter().all(|j| j.qname.ends_with(".example")));
    }

    #[test]
    fn seeds_are_reproducible() {
        let names = |seed| -> Vec<String> {
            build(&domains(4), &[], 1, true, &mut Rng::new(seed))
                .iter()
                .map(|j| j.qname.clone())
                .collect()
        };
        assert_eq!(names(7), names(7));
        assert_ne!(names(7), names(8));
    }

    #[test]
    fn shuffle_keeps_every_element() {
        let mut v: Vec<u32> = (0..64).collect();
        Rng::new(9).shuffle(&mut v);
        v.sort();
        assert_eq!(v, (0..64).collect::<Vec<_>>());
    }
}
