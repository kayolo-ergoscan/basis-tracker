use crate::models::TrackerEvent;
use std::sync::atomic::AtomicU64;
use tokio::sync::Mutex;

// Simple file-based event store with sequential IDs
pub struct EventStore {
    events: Mutex<Vec<TrackerEvent>>,
    next_id: AtomicU64,
}

impl EventStore {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // In a real implementation, this would load from disk
        // For now, we'll use in-memory but structured for easy disk persistence
        Ok(Self {
            events: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        })
    }

    pub async fn add_event(
        &self,
        mut event: TrackerEvent,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        event.id = id;

        // In a real implementation, this would append to a disk file
        // For now, we'll use a mutex-protected vector
        let mut events = self.events.lock().await;
        events.push(event);

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
        Ok(events[start..end].to_vec())
    }

    /// The `count` most recent events, oldest of them first.
    pub async fn get_recent_events(&self, count: usize) -> Vec<TrackerEvent> {
        let events = self.events.lock().await;
        events[events.len().saturating_sub(count)..].to_vec()
    }

    /// Create an in-memory event store for testing
    pub fn new_in_memory() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
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
