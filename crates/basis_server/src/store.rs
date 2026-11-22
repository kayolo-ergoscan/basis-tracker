use crate::models::TrackerEvent;
use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use tokio::sync::Mutex;

/// Most events the store keeps. Beyond it the oldest event is dropped for each new one, so the
/// log cannot grow without bound; ids keep counting, so a client sees where the log starts.
pub const MAX_EVENTS: usize = 10_000;

/// In-memory event log with sequential ids: the last [`MAX_EVENTS`] events.
pub struct EventStore {
    events: Mutex<VecDeque<TrackerEvent>>,
    next_id: AtomicU64,
}

impl EventStore {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // In a real implementation, this would load from disk
        // For now, we'll use in-memory but structured for easy disk persistence
        Ok(Self::new_in_memory())
    }

    pub async fn add_event(
        &self,
        mut event: TrackerEvent,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        event.id = id;

        let mut events = self.events.lock().await;
        if events.len() >= MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);

        Ok(id)
    }

    /// Page `page` (from 0) of `page_size` events, oldest first. A page past the end is empty;
    /// no `page`/`page_size` can overflow or panic.
    pub async fn get_events_paginated(
        &self,
        page: usize,
        page_size: usize,
    ) -> Result<Vec<TrackerEvent>, Box<dyn std::error::Error>> {
        let events = self.events.lock().await;
        let start = page.saturating_mul(page_size).min(events.len());
        let end = start.saturating_add(page_size).min(events.len());
        Ok(events.range(start..end).cloned().collect())
    }

    /// The `count` most recent events, oldest of them first.
    pub async fn get_recent_events(&self, count: usize) -> Vec<TrackerEvent> {
        let events = self.events.lock().await;
        events
            .range(events.len().saturating_sub(count)..)
            .cloned()
            .collect()
    }

    /// Create an empty in-memory event store.
    pub fn new_in_memory() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventType;

    async fn store_with(count: u64) -> EventStore {
        let store = EventStore::new_in_memory();
        for i in 0..count {
            let event = TrackerEvent {
                id: 0,
                event_type: EventType::NoteUpdated,
                timestamp: i,
                issuer_pubkey: None,
                recipient_pubkey: None,
                amount: Some(i),
                reserve_box_id: None,
                collateral_amount: None,
                redeemed_amount: None,
                height: None,
            };
            store.add_event(event).await.unwrap();
        }
        store
    }

    fn ids(events: &[TrackerEvent]) -> Vec<u64> {
        events.iter().map(|e| e.id).collect()
    }

    #[tokio::test]
    async fn pages_past_the_end_are_empty_and_nothing_overflows() {
        let store = store_with(5).await;
        let page = |page, size| store.get_events_paginated(page, size);
        assert_eq!(ids(&page(0, 2).await.unwrap()), [1, 2]);
        assert_eq!(ids(&page(2, 2).await.unwrap()), [5]);
        // Past the end used to slice events[6..5] and panic.
        assert!(page(3, 2).await.unwrap().is_empty());
        assert!(page(1_000, 20).await.unwrap().is_empty());
        // page * page_size and start + page_size used to overflow.
        assert!(page(usize::MAX, 2).await.unwrap().is_empty());
        assert!(page(2, usize::MAX).await.unwrap().is_empty());
        assert_eq!(ids(&page(0, usize::MAX).await.unwrap()), [1, 2, 3, 4, 5]);
        assert!(page(0, 0).await.unwrap().is_empty());
    }

    /// The log keeps the last MAX_EVENTS events: the oldest go first, ids keep counting.
    #[tokio::test]
    async fn the_log_keeps_the_last_max_events() {
        let store = store_with(MAX_EVENTS as u64 + 5).await;
        let first_page = store.get_events_paginated(0, 3).await.unwrap();
        assert_eq!(ids(&first_page), [6, 7, 8]);
        let all = store.get_events_paginated(0, usize::MAX).await.unwrap();
        assert_eq!(all.len(), MAX_EVENTS);
        assert_eq!(all.last().unwrap().id, MAX_EVENTS as u64 + 5);
        let last_page = store
            .get_events_paginated(MAX_EVENTS / 2 - 1, 2)
            .await
            .unwrap();
        assert_eq!(
            ids(&last_page),
            [MAX_EVENTS as u64 + 4, MAX_EVENTS as u64 + 5]
        );
        let recent = store.get_recent_events(2).await;
        assert_eq!(ids(&recent), [MAX_EVENTS as u64 + 4, MAX_EVENTS as u64 + 5]);
    }

    #[tokio::test]
    async fn recent_events_are_the_newest() {
        let store = store_with(60).await;
        let recent = store.get_recent_events(50).await;
        assert_eq!(ids(&recent), (11..=60).collect::<Vec<_>>());
        assert_eq!(
            ids(&store_with(3).await.get_recent_events(50).await),
            [1, 2, 3]
        );
    }
}
