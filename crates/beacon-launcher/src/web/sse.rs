//! `GET /api/events`: server-sent events. The first event is the full state;
//! after every change (coalesced, at most one per [`MIN_INTERVAL`], i.e. ≤ 10/s)
//! the full state again:
//!
//! ```text
//! event: state
//! data: {"version":"0.1.0","connection":{"state":"disconnected"},…}
//!
//! ```
//!
//! `event: quit` (data `{}`) ends the stream when Beacon shuts down. Comment lines
//! every [`KEEP_ALIVE`] keep idle connections open. One producer task per stream,
//! a channel of two events between it and the response body (a stalled client
//! holds at most that much; it is dropped after 30 s without progress).

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_core::Stream;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit};
use tokio::time::Instant;
use tracing::warn;

use super::api::ApiError;
use super::Shared;
use crate::app::App;
use crate::state::Change;

/// Shortest gap between two state events (at most 10 per second).
pub const MIN_INTERVAL: Duration = Duration::from_millis(100);
/// Interval of the keep-alive comments.
pub const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// A client that does not take an event within this time is dropped.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// The response body: events from the producer task.
struct EventStream(mpsc::Receiver<Event>);

impl Stream for EventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|event| event.map(Ok))
    }
}

pub(super) async fn events(State(s): State<Shared>) -> Response {
    let Ok(permit) = Arc::clone(&s.streams).try_acquire_owned() else {
        return ApiError::too_many_streams().into_response();
    };
    let (tx, rx) = mpsc::channel(2);
    tokio::spawn(produce(s.app.clone(), s.stop.clone(), tx, permit));
    Sse::new(EventStream(rx))
        .keep_alive(KeepAlive::new().interval(KEEP_ALIVE))
        .into_response()
}

fn state_event(app: &App) -> Option<Event> {
    match Event::default().event("state").json_data(app.snapshot()) {
        Ok(event) => Some(event),
        Err(e) => {
            warn!("cannot serialise the state: {e}");
            None
        }
    }
}

async fn sleep_until(due: Option<Instant>) {
    match due {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// Resolves once the server stops (or is gone).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// Sends `event`; `false` if the client is gone or stalled.
async fn deliver(tx: &mpsc::Sender<Event>, event: Event) -> bool {
    matches!(tokio::time::timeout(SEND_TIMEOUT, tx.send(event)).await, Ok(Ok(())))
}

async fn produce(app: App, mut stop: watch::Receiver<bool>, tx: mpsc::Sender<Event>, _permit: OwnedSemaphorePermit) {
    // Subscribed before the first snapshot: no change can fall in between.
    let mut changes = app.subscribe();
    let mut dirty = true;
    let mut last_sent: Option<Instant> = None;
    loop {
        let due = dirty.then(|| last_sent.map_or_else(Instant::now, |t| t + MIN_INTERVAL));
        tokio::select! {
            biased;
            () = tx.closed() => return,
            () = stopped(&mut stop) => return,
            change = changes.recv() => match change {
                Ok(Change::Quit) | Err(RecvError::Closed) => {
                    deliver(&tx, Event::default().event("quit").data("{}")).await;
                    return;
                }
                Ok(Change::Activate) => {}
                Ok(_) | Err(RecvError::Lagged(_)) => dirty = true,
            },
            () = sleep_until(due) => {
                if let Some(event) = state_event(&app) {
                    if !deliver(&tx, event).await {
                        return;
                    }
                }
                last_sent = Some(Instant::now());
                dirty = false;
            }
        }
    }
}
