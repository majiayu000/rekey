use axum::response::sse::{Event, KeepAlive, Sse};
use std::convert::Infallible;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrafficEvent {
    pub timestamp: i64,
    pub secret_name: String,
    pub target_host: String,
    pub target_path: String,
    pub status_code: Option<i32>,
    pub latency_ms: Option<i64>,
    pub source: String,
}

pub type TrafficBroadcaster = broadcast::Sender<TrafficEvent>;

pub fn new_broadcaster(capacity: usize) -> TrafficBroadcaster {
    let (tx, _) = broadcast::channel(capacity);
    tx
}

pub fn emit_traffic(tx: &TrafficBroadcaster, event: TrafficEvent) {
    let _ = tx.send(event);
}

pub fn traffic_sse(
    tx: TrafficBroadcaster,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(tx.subscribe()).filter_map(|message| match message {
        Ok(event) => Some(Ok(Event::default()
            .json_data(event)
            .unwrap_or_else(|_| Event::default().data("{\"error\":\"serialize\"}")))),
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
}
