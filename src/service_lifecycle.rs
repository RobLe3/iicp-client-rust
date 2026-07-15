// SPDX-License-Identifier: Apache-2.0
//! Opt-in reference adapter for the pre-normative service-lifecycle profile.
//!
//! The router is never mounted by the normal node unless an integrator chooses
//! to do so. It therefore adds no wire behavior to the ratified CALL/RESPONSE
//! path and keeps model/runtime scheduling outside the profile.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub const PROFILE: &str = "urn:iicp:profile:service-lifecycle:v1";

#[derive(Clone, Debug, Serialize)]
pub struct LifecycleEvent {
    pub task_id: String,
    pub sequence: u64,
    pub state: String,
    pub is_final: bool,
    pub observed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

#[derive(Clone, Debug)]
pub struct LifecycleRecord {
    pub task_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub state: String,
    pub events: Vec<LifecycleEvent>,
    pub updated_at_ms: u64,
}

impl LifecycleRecord {
    pub fn latest_sequence(&self) -> u64 {
        self.events.last().map_or(0, |event| event.sequence)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    Conflict(String),
    UnknownTask,
    ResumeUnavailable { state: String, latest_sequence: u64 },
}

#[derive(Clone)]
pub struct LifecycleStore {
    records: Arc<Mutex<HashMap<String, LifecycleRecord>>>,
    max_events: usize,
    terminal_status_ttl_ms: u64,
}

impl LifecycleStore {
    pub fn new(max_events: usize, terminal_status_ttl_ms: u64) -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            max_events: max_events.max(2),
            terminal_status_ttl_ms,
        }
    }

    pub async fn submit(
        &self,
        task_id: &str,
        idempotency_key: &str,
        request_digest: &str,
    ) -> Result<(LifecycleRecord, bool), LifecycleError> {
        let mut records = self.records.lock().await;
        if let Some(existing) = records.get(task_id) {
            if existing.idempotency_key != idempotency_key
                || existing.request_digest != request_digest
            {
                return Err(LifecycleError::Conflict(
                    "task or idempotency identifier reused for different content".into(),
                ));
            }
            return Ok((existing.clone(), false));
        }
        if records
            .values()
            .any(|record| record.idempotency_key == idempotency_key)
        {
            return Err(LifecycleError::Conflict(
                "idempotency identifier reused with a different task identifier".into(),
            ));
        }
        let now = now_ms();
        let event = LifecycleEvent {
            task_id: task_id.into(),
            sequence: 0,
            state: "accepted".into(),
            is_final: false,
            observed_at_ms: now,
            detail: Value::Null,
        };
        let record = LifecycleRecord {
            task_id: task_id.into(),
            idempotency_key: idempotency_key.into(),
            request_digest: request_digest.into(),
            state: "accepted".into(),
            events: vec![event],
            updated_at_ms: now,
        };
        records.insert(task_id.into(), record.clone());
        Ok((record, true))
    }

    pub async fn status(&self, task_id: &str) -> Result<LifecycleRecord, LifecycleError> {
        let mut records = self.records.lock().await;
        let expired = records.get(task_id).is_some_and(|record| {
            terminal(&record.state)
                && now_ms().saturating_sub(record.updated_at_ms) > self.terminal_status_ttl_ms
        });
        if expired {
            records.remove(task_id);
        }
        records
            .get(task_id)
            .cloned()
            .ok_or(LifecycleError::UnknownTask)
    }

    pub async fn transition(
        &self,
        task_id: &str,
        requested_state: &str,
        detail: Value,
    ) -> Result<LifecycleEvent, LifecycleError> {
        let mut records = self.records.lock().await;
        let record = records
            .get_mut(task_id)
            .ok_or(LifecycleError::UnknownTask)?;
        let state = if requested_state == "timed_out" {
            "expired"
        } else {
            requested_state
        };
        if !legal_transition(&record.state, state) {
            return Err(LifecycleError::Conflict(format!(
                "illegal transition {} -> {state}",
                record.state
            )));
        }
        let now = now_ms();
        let event = LifecycleEvent {
            task_id: task_id.into(),
            sequence: record.latest_sequence() + 1,
            state: state.into(),
            is_final: terminal(state),
            observed_at_ms: now,
            detail,
        };
        record.events.push(event.clone());
        if record.events.len() > self.max_events {
            let excess = record.events.len() - self.max_events;
            record.events.drain(0..excess);
        }
        record.state = state.into();
        record.updated_at_ms = now;
        Ok(event)
    }

    pub async fn cancel(&self, task_id: &str) -> Result<LifecycleRecord, LifecycleError> {
        let current = self.status(task_id).await?;
        if !terminal(&current.state) {
            self.transition(task_id, "cancelled", json!({"outcome": "cancelled"}))
                .await?;
        }
        self.status(task_id).await
    }

    pub async fn events_after(
        &self,
        task_id: &str,
        after_sequence: i64,
    ) -> Result<Vec<LifecycleEvent>, LifecycleError> {
        let record = self.status(task_id).await?;
        let first = record.events.first().map_or(0, |event| event.sequence);
        if after_sequence >= 0 && (after_sequence as u64).saturating_add(1) < first {
            let latest_sequence = record.latest_sequence();
            return Err(LifecycleError::ResumeUnavailable {
                state: record.state,
                latest_sequence,
            });
        }
        Ok(record
            .events
            .into_iter()
            .filter(|event| event.sequence as i64 > after_sequence)
            .collect())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn terminal(state: &str) -> bool {
    matches!(
        state,
        "rejected" | "completed" | "failed" | "cancelled" | "expired"
    )
}

fn legal_transition(from: &str, to: &str) -> bool {
    match from {
        "submitted" => matches!(to, "accepted" | "rejected" | "expired"),
        "accepted" => matches!(
            to,
            "queued" | "running" | "completed" | "cancelled" | "failed" | "expired"
        ),
        "queued" => matches!(
            to,
            "running" | "waiting" | "cancelled" | "failed" | "expired"
        ),
        "running" => matches!(
            to,
            "waiting" | "streaming" | "completed" | "cancelled" | "failed" | "expired"
        ),
        "waiting" => matches!(
            to,
            "queued" | "running" | "cancelled" | "failed" | "expired"
        ),
        "streaming" => matches!(
            to,
            "streaming" | "waiting" | "completed" | "cancelled" | "failed" | "expired"
        ),
        _ => false,
    }
}

#[derive(Clone)]
struct HttpState {
    store: LifecycleStore,
    bearer_token: String,
}

#[derive(Deserialize)]
struct SubmitRequest {
    task_id: String,
    idempotency_key: String,
    request_digest: String,
}

#[derive(Deserialize)]
struct ObserveQuery {
    #[serde(default = "default_after")]
    after_sequence: i64,
}

fn default_after() -> i64 {
    -1
}

fn authorized(headers: &HeaderMap, state: &HttpState) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {}", state.bearer_token))
}

fn record_json(record: &LifecycleRecord) -> Value {
    json!({
        "profile": PROFILE,
        "task_id": record.task_id,
        "state": record.state,
        "latest_sequence": record.latest_sequence(),
        "is_final": terminal(&record.state),
    })
}

fn lifecycle_error(error: LifecycleError) -> Response {
    match error {
        LifecycleError::UnknownTask => (StatusCode::NOT_FOUND, Json(json!({"code": "unknown_task"}))).into_response(),
        LifecycleError::Conflict(message) => (StatusCode::CONFLICT, Json(json!({"code": "conflict", "message": message}))).into_response(),
        LifecycleError::ResumeUnavailable { state, latest_sequence } => (
            StatusCode::CONFLICT,
            Json(json!({"code": "resume_unavailable", "state": state, "latest_sequence": latest_sequence})),
        ).into_response(),
    }
}

async fn submit_http(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<SubmitRequest>,
) -> Response {
    if !authorized(&headers, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state
        .store
        .submit(&body.task_id, &body.idempotency_key, &body.request_digest)
        .await
    {
        Ok((record, created)) => (
            if created {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            },
            Json(record_json(&record)),
        )
            .into_response(),
        Err(error) => lifecycle_error(error),
    }
}

async fn status_http(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Response {
    if !authorized(&headers, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.store.status(&task_id).await {
        Ok(record) => Json(record_json(&record)).into_response(),
        Err(error) => lifecycle_error(error),
    }
}

async fn observe_http(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    Query(query): Query<ObserveQuery>,
) -> Response {
    if !authorized(&headers, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state
        .store
        .events_after(&task_id, query.after_sequence)
        .await
    {
        Ok(events) => {
            let body = events
                .into_iter()
                .map(|event| serde_json::to_string(&event).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            ([(header::CONTENT_TYPE, "application/x-ndjson")], body).into_response()
        }
        Err(error) => lifecycle_error(error),
    }
}

async fn cancel_http(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Response {
    if !authorized(&headers, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.store.cancel(&task_id).await {
        Ok(record) => Json(record_json(&record)).into_response(),
        Err(error) => lifecycle_error(error),
    }
}

/// Build the draft HTTP binding. Calling this function is the profile opt-in.
pub fn lifecycle_router(store: LifecycleStore, bearer_token: impl Into<String>) -> Router {
    let state = HttpState {
        store,
        bearer_token: bearer_token.into(),
    };
    Router::new()
        .route("/v1/tasks", post(submit_http))
        .route("/v1/tasks/:task_id", get(status_http))
        .route("/v1/tasks/:task_id/events", get(observe_http))
        .route("/v1/tasks/:task_id/cancel", post(cancel_http))
        .with_state(state)
}
