//! Latency summary statistics.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub samples: usize,
    pub min: f64,
    pub avg: f64,
    pub median: f64,
    pub p95: f64,
    pub max: f64,
    pub stddev: f64,
    /// Mean absolute difference between consecutive samples.
    pub jitter: f64,
}

impl Stats {
    /// `ms` is in arrival order; percentiles sort a copy.
    pub fn from_samples(ms: &[f64]) -> Option<Stats> {
        if ms.is_empty() {
            return None;
        }
        let n = ms.len() as f64;
        let avg = ms.iter().sum::<f64>() / n;
        let variance = ms.iter().map(|v| (v - avg).powi(2)).sum::<f64>() / n;
        let jitter = if ms.len() > 1 {
            ms.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (n - 1.0)
        } else {
            0.0
        };

        let mut sorted = ms.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        Some(Stats {
            samples: ms.len(),
            min: sorted[0],
            avg,
            median: percentile(&sorted, 50.0),
            p95: percentile(&sorted, 95.0),
            max: sorted[sorted.len() - 1],
            stddev: variance.sqrt(),
            jitter,
        })
    }
}

/// Nearest-rank percentile over an already-sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (p / 100.0 * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarises() {
        let s = Stats::from_samples(&[10.0, 20.0, 30.0, 40.0]).unwrap();
        assert_eq!(s.samples, 4);
        assert_eq!(s.min, 10.0);
        assert_eq!(s.max, 40.0);
        assert_eq!(s.avg, 25.0);
        assert_eq!(s.median, 20.0);
        assert_eq!(s.p95, 40.0);
        assert!((s.jitter - 10.0).abs() < 1e-9);
    }

    #[test]
    fn empty_is_none() {
        assert!(Stats::from_samples(&[]).is_none());
    }

    #[test]
    fn single_sample() {
        let s = Stats::from_samples(&[7.0]).unwrap();
        assert_eq!(s.median, 7.0);
        assert_eq!(s.stddev, 0.0);
        assert_eq!(s.jitter, 0.0);
    }
}
