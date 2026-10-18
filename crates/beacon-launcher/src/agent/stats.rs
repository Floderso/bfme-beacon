//! Relay path measurements from the agent's 1 s PING/PONG: RTT as an EWMA
//! (α = 1/8, like TCP's SRTT) and packet loss over the last [`LOSS_WINDOW`] pings.

use std::collections::VecDeque;

/// Pings considered for the loss estimate.
pub const LOSS_WINDOW: usize = 30;
/// A ping counts as lost if unanswered for this long.
pub const PONG_GRACE_MS: u64 = 3000;
/// RTT samples above this are ignored (clock nonsense).
const MAX_RTT_MS: u64 = 60_000;

/// Smoothed round-trip time.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RttEstimator {
    srtt: Option<f64>,
}

impl RttEstimator {
    /// Adds a sample (ms).
    pub fn sample(&mut self, rtt_ms: u64) {
        if rtt_ms > MAX_RTT_MS {
            return;
        }
        let x = rtt_ms as f64;
        self.srtt = Some(match self.srtt {
            None => x,
            Some(s) => s + (x - s) / 8.0,
        });
    }

    /// The smoothed RTT in whole ms.
    pub fn rtt_ms(&self) -> Option<u32> {
        self.srtt.map(|s| s.round().clamp(0.0, f64::from(u32::MAX)) as u32)
    }

    /// Forgets everything (new session).
    pub fn reset(&mut self) {
        self.srtt = None;
    }
}

/// Loss over the last pings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LossWindow {
    pings: VecDeque<(u64, bool)>,
}

impl LossWindow {
    /// The timestamp for a ping sent at `now` (ms): `now`, or one more than the
    /// newest recorded ping. Pongs are matched by timestamp, so two pings in one
    /// millisecond would make the second pong look like a duplicate (a false loss).
    pub fn stamp(&self, now: u64) -> u64 {
        self.pings
            .back()
            .map_or(now, |&(last, _)| now.max(last.saturating_add(1)))
    }

    /// A ping with timestamp `ts` (ms, strictly increasing: see [`stamp`](Self::stamp)) was sent.
    pub fn sent(&mut self, ts: u64) {
        if self.pings.len() >= LOSS_WINDOW {
            self.pings.pop_front();
        }
        self.pings.push_back((ts, false));
    }

    /// A pong for `ts` arrived at `now`; returns the RTT for a known, unanswered
    /// ping (duplicates and unknown timestamps give `None`).
    pub fn answered(&mut self, ts: u64, now: u64) -> Option<u64> {
        let entry = self.pings.iter_mut().find(|(t, _)| *t == ts)?;
        if entry.1 {
            return None;
        }
        entry.1 = true;
        now.checked_sub(ts)
    }

    /// Loss in percent among pings older than [`PONG_GRACE_MS`]; `None` without
    /// such pings.
    pub fn loss_pct(&self, now: u64) -> Option<u8> {
        let (mut total, mut lost) = (0u32, 0u32);
        for &(ts, answered) in &self.pings {
            if now.saturating_sub(ts) >= PONG_GRACE_MS {
                total += 1;
                lost += u32::from(!answered);
            }
        }
        (total > 0).then(|| u8::try_from((lost * 100 + total / 2) / total).unwrap_or(100))
    }

    /// Forgets everything (new session).
    pub fn reset(&mut self) {
        self.pings.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_ewma() {
        let mut r = RttEstimator::default();
        assert_eq!(r.rtt_ms(), None);
        r.sample(40);
        assert_eq!(r.rtt_ms(), Some(40));
        r.sample(120);
        assert_eq!(r.rtt_ms(), Some(50));
        r.sample(MAX_RTT_MS + 1);
        assert_eq!(r.rtt_ms(), Some(50));
        for _ in 0..100 {
            r.sample(10);
        }
        assert_eq!(r.rtt_ms(), Some(10));
        r.reset();
        assert_eq!(r.rtt_ms(), None);
    }

    #[test]
    fn pings_in_one_millisecond_get_distinct_stamps() {
        let mut w = LossWindow::default();
        let a = w.stamp(40);
        w.sent(a);
        let b = w.stamp(40);
        w.sent(b);
        assert_eq!((a, b), (40, 41));
        assert_eq!(w.answered(a, 45), Some(5));
        assert_eq!(w.answered(b, 45), Some(4), "the second pong is not a duplicate");
        assert_eq!(w.stamp(100), 100);
        assert_eq!(w.loss_pct(10_000), Some(0));
    }

    #[test]
    fn loss_window() {
        let mut w = LossWindow::default();
        assert_eq!(w.loss_pct(0), None);
        for i in 0..10u64 {
            w.sent(i * 1000);
        }
        // Pings 0..=7 are old enough at t=10_000 (8 of them); answer 6.
        for i in [0u64, 1, 2, 3, 5, 6] {
            assert_eq!(w.answered(i * 1000, i * 1000 + 25), Some(25));
        }
        assert_eq!(w.answered(0, 99), None, "duplicate pong");
        assert_eq!(w.answered(12_345, 99), None, "unknown ping");
        assert_eq!(w.loss_pct(10_000), Some(25));
        for i in 10..100u64 {
            w.sent(i * 1000);
            w.answered(i * 1000, i * 1000 + 1);
        }
        assert_eq!(w.loss_pct(200_000), Some(0), "old losses leave the window");
        w.reset();
        assert_eq!(w.loss_pct(200_000), None);
    }
}
