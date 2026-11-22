//! Limits on `POST /notes` (round 4, C3).
//!
//! The note route is open to people, and every accepted note is an edge of the tracker tree that
//! every commit carries and every rebuild walks. Four caps bound it, each answered with
//! `429 Too Many Requests`:
//!
//! * `server.notes_max_recipients_per_issuer` (default 50): distinct recipients of one issuer;
//! * `server.notes_max_updates_per_issuer_per_hour` (default 120): accepted notes (new or
//!   raised) of one issuer per rolling hour;
//! * `server.notes_max_new_edges_per_issuer_per_hour` (default 10, round 5): new edges of one
//!   issuer per rolling hour, so it takes many issuers, each with an active reserve, to use up
//!   the next cap;
//! * `server.notes_max_new_edges_per_hour` (default 1000): new (issuer, recipient,
//!   denomination) edges per rolling hour, all issuers together.
//!
//! Only accepted notes count: a note the tracker refuses (bad signature, old timestamp, ...)
//! gives its slot back. Admission is serialized ([`NoteLimiter::admit`] is held from the cap
//! checks to the tracker's answer), so concurrent requests cannot overshoot a cap; the tracker
//! thread handles notes one at a time anyway.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use basis_store::PubKey;

/// The rolling window of the hourly caps.
pub const NOTE_WINDOW: Duration = Duration::from_secs(3600);
/// How often the whole per-issuer table is swept for issuers with nothing left in the window.
const NOTE_WINDOW_SWEEP_EVERY: Duration = Duration::from_secs(60);
/// Issuers the per-issuer window tracks at most. A new issuer beyond it is refused (429) until
/// older entries age out, rather than evicting an issuer's history.
pub const MAX_TRACKED_NOTE_ISSUERS: usize = 10_000;

#[derive(Debug)]
struct Windows {
    per_issuer: HashMap<PubKey, VecDeque<Instant>>,
    /// The new edges of each issuer (a subset of the issuer's entries in `per_issuer`).
    per_issuer_new_edges: HashMap<PubKey, VecDeque<Instant>>,
    new_edges: VecDeque<Instant>,
    last_sweep: Instant,
}

/// The hourly caps [`NoteLimiter::try_record`] checks.
#[derive(Debug, Clone, Copy)]
pub struct NoteCaps {
    /// `server.notes_max_updates_per_issuer_per_hour`.
    pub updates_per_issuer: u32,
    /// `server.notes_max_new_edges_per_issuer_per_hour`.
    pub new_edges_per_issuer: u32,
    /// `server.notes_max_new_edges_per_hour`.
    pub new_edges: u32,
}

impl NoteCaps {
    /// The caps of a `[server]` config.
    pub fn of(server: &crate::config::ServerConfig) -> Self {
        Self {
            updates_per_issuer: server.notes_max_updates_per_issuer_per_hour,
            new_edges_per_issuer: server.notes_max_new_edges_per_issuer_per_hour,
            new_edges: server.notes_max_new_edges_per_hour,
        }
    }
}

/// One recorded note, given back with [`NoteLimiter::release`] when the tracker refuses it.
#[derive(Debug, Clone, Copy)]
#[must_use = "release the slot when the tracker refuses the note"]
pub struct NoteSlot {
    issuer: PubKey,
    at: Instant,
    new_edge: bool,
}

/// The hourly note caps and the admission lock of `POST /notes`.
#[derive(Debug)]
pub struct NoteLimiter {
    admission: tokio::sync::Mutex<()>,
    windows: std::sync::Mutex<Windows>,
}

impl Default for NoteLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteLimiter {
    pub fn new() -> Self {
        Self {
            admission: tokio::sync::Mutex::new(()),
            windows: std::sync::Mutex::new(Windows {
                per_issuer: HashMap::new(),
                per_issuer_new_edges: HashMap::new(),
                new_edges: VecDeque::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Serialize note admission: hold the guard from the cap checks to the tracker's answer.
    pub async fn admit(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.admission.lock().await
    }

    /// Check the hourly caps for one more note of `issuer` (`new_edge`: the note creates an
    /// edge) and record it. `Err` carries the message for the 429.
    pub fn try_record(
        &self,
        issuer: &PubKey,
        new_edge: bool,
        caps: NoteCaps,
    ) -> Result<NoteSlot, String> {
        let now = Instant::now();
        let mut windows = self.lock();
        Self::prune(&mut windows, issuer, now);

        let posted = windows.per_issuer.get(issuer).map_or(0, VecDeque::len);
        if posted >= caps.updates_per_issuer as usize {
            return Err(format!(
                "issuer {} posted {} notes in the last hour, the most this tracker accepts \
                 (server.notes_max_updates_per_issuer_per_hour = {}); try again later",
                hex::encode(issuer),
                posted,
                caps.updates_per_issuer
            ));
        }
        let issuer_new_edges = windows
            .per_issuer_new_edges
            .get(issuer)
            .map_or(0, VecDeque::len);
        if new_edge && issuer_new_edges >= caps.new_edges_per_issuer as usize {
            return Err(format!(
                "issuer {} created {} new debt edges in the last hour, the most this tracker \
                 accepts from one issuer (server.notes_max_new_edges_per_issuer_per_hour = {}); \
                 a note to a new recipient or in a new denomination must wait",
                hex::encode(issuer),
                issuer_new_edges,
                caps.new_edges_per_issuer
            ));
        }
        if new_edge && windows.new_edges.len() >= caps.new_edges as usize {
            return Err(format!(
                "{} new debt edges were created in the last hour, the most this tracker accepts \
                 (server.notes_max_new_edges_per_hour = {}); a note to a new recipient or in a \
                 new denomination must wait",
                windows.new_edges.len(),
                caps.new_edges
            ));
        }
        if !windows.per_issuer.contains_key(issuer)
            && windows.per_issuer.len() >= MAX_TRACKED_NOTE_ISSUERS
        {
            return Err(
                "too many issuers posted notes in the last hour; try again later".to_string(),
            );
        }

        windows.per_issuer.entry(*issuer).or_default().push_back(now);
        if new_edge {
            windows.new_edges.push_back(now);
            windows
                .per_issuer_new_edges
                .entry(*issuer)
                .or_default()
                .push_back(now);
        }
        Ok(NoteSlot {
            issuer: *issuer,
            at: now,
            new_edge,
        })
    }

    /// Give back a slot whose note the tracker refused.
    pub fn release(&self, slot: NoteSlot) {
        let mut windows = self.lock();
        if let Some(queue) = windows.per_issuer.get_mut(&slot.issuer) {
            if let Some(i) = queue.iter().rposition(|t| *t == slot.at) {
                queue.remove(i);
            }
            if queue.is_empty() {
                windows.per_issuer.remove(&slot.issuer);
            }
        }
        if slot.new_edge {
            if let Some(i) = windows.new_edges.iter().rposition(|t| *t == slot.at) {
                windows.new_edges.remove(i);
            }
            if let Some(queue) = windows.per_issuer_new_edges.get_mut(&slot.issuer) {
                if let Some(i) = queue.iter().rposition(|t| *t == slot.at) {
                    queue.remove(i);
                }
                if queue.is_empty() {
                    windows.per_issuer_new_edges.remove(&slot.issuer);
                }
            }
        }
    }

    /// Drop what left the window: `issuer`'s entries and the new-edge entries on every call,
    /// every issuer's once a minute.
    fn prune(windows: &mut Windows, issuer: &PubKey, now: Instant) {
        let fresh = |t: &Instant| now.duration_since(*t) < NOTE_WINDOW;
        while windows.new_edges.front().is_some_and(|t| !fresh(t)) {
            windows.new_edges.pop_front();
        }
        for map in [&mut windows.per_issuer, &mut windows.per_issuer_new_edges] {
            if let Some(queue) = map.get_mut(issuer) {
                while queue.front().is_some_and(|t| !fresh(t)) {
                    queue.pop_front();
                }
                if queue.is_empty() {
                    map.remove(issuer);
                }
            }
        }
        if now.duration_since(windows.last_sweep) >= NOTE_WINDOW_SWEEP_EVERY {
            for map in [&mut windows.per_issuer, &mut windows.per_issuer_new_edges] {
                map.retain(|_, queue| {
                    while queue.front().is_some_and(|t| !fresh(t)) {
                        queue.pop_front();
                    }
                    !queue.is_empty()
                });
            }
            windows.last_sweep = now;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Windows> {
        // Each entry is independent, so a panic while holding the lock leaves a usable map.
        self.windows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: PubKey = [0x02; 33];
    const B: PubKey = [0x03; 33];

    /// `updates` per issuer and `new_edges` in total; no per-issuer new-edge cap.
    fn caps(updates: u32, new_edges: u32) -> NoteCaps {
        NoteCaps {
            updates_per_issuer: updates,
            new_edges_per_issuer: u32::MAX,
            new_edges,
        }
    }

    #[test]
    fn the_per_issuer_cap_counts_every_note_of_the_issuer() {
        let limiter = NoteLimiter::new();
        let _ = limiter.try_record(&A, true, caps(2, 100)).unwrap();
        let _ = limiter.try_record(&A, false, caps(2, 100)).unwrap();
        let err = limiter.try_record(&A, false, caps(2, 100)).unwrap_err();
        assert!(err.contains("notes_max_updates_per_issuer_per_hour"), "{err}");
        // Another issuer has its own budget.
        let _ = limiter.try_record(&B, false, caps(2, 100)).unwrap();
    }

    #[test]
    fn the_new_edge_cap_counts_only_new_edges_of_all_issuers() {
        let limiter = NoteLimiter::new();
        let _ = limiter.try_record(&A, true, caps(100, 2)).unwrap();
        let _ = limiter.try_record(&B, true, caps(100, 2)).unwrap();
        let err = limiter.try_record(&A, true, caps(100, 2)).unwrap_err();
        assert!(err.contains("notes_max_new_edges_per_hour"), "{err}");
        // Raising an existing edge is not a new edge.
        let _ = limiter.try_record(&A, false, caps(100, 2)).unwrap();
    }

    /// Round 5, item 6: one issuer's new edges are capped on their own, below the total, so it
    /// takes many issuers to use up the total; raising an edge is not a new one.
    #[test]
    fn the_per_issuer_new_edge_cap_counts_only_that_issuers_new_edges() {
        let limiter = NoteLimiter::new();
        let caps = NoteCaps {
            updates_per_issuer: 100,
            new_edges_per_issuer: 2,
            new_edges: 3,
        };
        let _ = limiter.try_record(&A, true, caps).unwrap();
        let _ = limiter.try_record(&A, true, caps).unwrap();
        let err = limiter.try_record(&A, true, caps).unwrap_err();
        assert!(err.contains("notes_max_new_edges_per_issuer_per_hour"), "{err}");
        assert!(err.contains(&hex::encode(A)), "{err}");
        // Raising an existing edge is still fine, and another issuer has its own budget...
        let _ = limiter.try_record(&A, false, caps).unwrap();
        let slot = limiter.try_record(&B, true, caps).unwrap();
        // ... up to the total.
        let err = limiter.try_record(&B, true, caps).unwrap_err();
        assert!(err.contains("notes_max_new_edges_per_hour"), "{err}");
        // A refused note gives its per-issuer slot back too.
        limiter.release(slot);
        let _ = limiter.try_record(&B, true, caps).unwrap();
    }

    #[test]
    fn a_released_slot_is_given_back() {
        let limiter = NoteLimiter::new();
        let slot = limiter.try_record(&A, true, caps(1, 1)).unwrap();
        assert!(limiter.try_record(&A, true, caps(1, 1)).is_err());
        limiter.release(slot);
        let _ = limiter.try_record(&A, true, caps(1, 1)).unwrap();
    }

    #[test]
    fn entries_older_than_an_hour_age_out() {
        let limiter = NoteLimiter::new();
        {
            let mut windows = limiter.lock();
            let old = Instant::now() - NOTE_WINDOW - Duration::from_secs(1);
            windows.per_issuer.insert(A, VecDeque::from([old, old]));
            windows.per_issuer_new_edges.insert(A, VecDeque::from([old, old]));
            windows.new_edges.extend([old, old]);
        }
        let one_each = NoteCaps {
            updates_per_issuer: 1,
            new_edges_per_issuer: 1,
            new_edges: 1,
        };
        let _ = limiter.try_record(&A, true, one_each).unwrap();
        assert_eq!(limiter.lock().new_edges.len(), 1);
        assert_eq!(limiter.lock().per_issuer_new_edges[&A].len(), 1);
    }

    #[test]
    fn the_issuer_table_is_bounded() {
        let limiter = NoteLimiter::new();
        {
            let mut windows = limiter.lock();
            let now = Instant::now();
            for i in 0..MAX_TRACKED_NOTE_ISSUERS {
                let mut key = [0u8; 33];
                key[..8].copy_from_slice(&(i as u64).to_be_bytes());
                windows.per_issuer.insert(key, VecDeque::from([now]));
            }
        }
        assert!(limiter.try_record(&A, false, caps(10, 10)).is_err());
    }
}
