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
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub const PROFILE: &str = "urn:iicp:profile:service-lifecycle:v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub task_id: String,
    pub sequence: u64,
    pub state: String,
    pub is_final: bool,
    pub observed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleRecord {
    pub task_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub state: String,
    pub events: Vec<LifecycleEvent>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleSnapshot {
    pub profile: String,
    pub records: Vec<LifecycleRecord>,
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
    Storage(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverLagged {
    pub earliest_available: u64,
    pub latest_sequence: u64,
}

type CancelHandler = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Clone, Default)]
pub struct BackendCancellationRegistry {
    handlers: Arc<StdMutex<HashMap<String, CancelHandler>>>,
    signalled: Arc<StdMutex<HashSet<String>>>,
}

impl BackendCancellationRegistry {
    pub fn register<F>(&self, task_id: impl Into<String>, handler: F)
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        let task_id = task_id.into();
        self.handlers
            .lock()
            .expect("cancellation registry lock")
            .insert(task_id.clone(), Arc::new(handler));
        self.signalled
            .lock()
            .expect("cancellation signal lock")
            .remove(&task_id);
    }

    pub fn complete(&self, task_id: &str) {
        self.handlers
            .lock()
            .expect("cancellation registry lock")
            .remove(task_id);
        self.signalled
            .lock()
            .expect("cancellation signal lock")
            .remove(task_id);
    }

    pub fn request(&self, task_id: &str, state: &str) -> &'static str {
        if terminal(state) {
            self.complete(task_id);
            return "already_terminal";
        }
        if self
            .signalled
            .lock()
            .expect("cancellation signal lock")
            .contains(task_id)
        {
            return "cancel_signalled";
        }
        let handler = self
            .handlers
            .lock()
            .expect("cancellation registry lock")
            .get(task_id)
            .cloned();
        let Some(handler) = handler else {
            return "cancel_unsupported";
        };
        if !handler() {
            return "cancel_unsupported";
        }
        self.signalled
            .lock()
            .expect("cancellation signal lock")
            .insert(task_id.into());
        "cancel_signalled"
    }
}

#[derive(Clone)]
pub struct BoundedObserverBuffer {
    state: Arc<StdMutex<ObserverState>>,
    capacity: usize,
    max_observers: usize,
}

#[derive(Default)]
struct ObserverState {
    events: VecDeque<LifecycleEvent>,
    observers: HashSet<String>,
    closed: bool,
}

impl BoundedObserverBuffer {
    pub fn new(capacity: usize, max_observers: usize) -> Self {
        Self {
            state: Arc::new(StdMutex::new(ObserverState::default())),
            capacity: capacity.max(1),
            max_observers: max_observers.max(1),
        }
    }

    pub fn subscribe(&self, observer_id: &str) -> Result<(), LifecycleError> {
        let mut state = self.state.lock().expect("observer lock");
        if !state.observers.contains(observer_id) && state.observers.len() >= self.max_observers {
            return Err(LifecycleError::Conflict(
                "observer capacity exhausted".into(),
            ));
        }
        state.observers.insert(observer_id.into());
        Ok(())
    }

    pub fn disconnect(&self, observer_id: &str) {
        self.state
            .lock()
            .expect("observer lock")
            .observers
            .remove(observer_id);
    }

    pub fn publish(&self, event: LifecycleEvent) -> Result<(), LifecycleError> {
        let mut state = self.state.lock().expect("observer lock");
        if state
            .events
            .back()
            .is_some_and(|last| event.sequence <= last.sequence)
        {
            return Err(LifecycleError::Conflict(
                "observer sequence must increase".into(),
            ));
        }
        state.closed = event.is_final;
        state.events.push_back(event);
        while state.events.len() > self.capacity {
            state.events.pop_front();
        }
        Ok(())
    }

    pub fn poll(&self, after_sequence: u64) -> Result<Vec<LifecycleEvent>, ObserverLagged> {
        let state = self.state.lock().expect("observer lock");
        if let (Some(first), Some(last)) = (state.events.front(), state.events.back()) {
            if after_sequence.saturating_add(1) < first.sequence {
                return Err(ObserverLagged {
                    earliest_available: first.sequence,
                    latest_sequence: last.sequence,
                });
            }
        }
        Ok(state
            .events
            .iter()
            .filter(|event| event.sequence > after_sequence)
            .cloned()
            .collect())
    }

    pub fn observer_count(&self) -> usize {
        self.state.lock().expect("observer lock").observers.len()
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().expect("observer lock").closed
    }
}

pub type LifecycleFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LifecycleError>> + Send + 'a>>;

/// Storage port for the opt-in lifecycle profile.
///
/// Persistence formats are implementation-specific. Implementations preserve
/// task/idempotency binding, ordered events, bounded replay and terminal TTL.
pub trait LifecyclePersistence: Send + Sync {
    fn submit<'a>(
        &'a self,
        task_id: &'a str,
        idempotency_key: &'a str,
        request_digest: &'a str,
    ) -> LifecycleFuture<'a, (LifecycleRecord, bool)>;
    fn status<'a>(&'a self, task_id: &'a str) -> LifecycleFuture<'a, LifecycleRecord>;
    fn transition<'a>(
        &'a self,
        task_id: &'a str,
        state: &'a str,
        detail: Value,
    ) -> LifecycleFuture<'a, LifecycleEvent>;
    fn cancel<'a>(&'a self, task_id: &'a str) -> LifecycleFuture<'a, LifecycleRecord>;
    fn events_after<'a>(
        &'a self,
        task_id: &'a str,
        after_sequence: i64,
    ) -> LifecycleFuture<'a, Vec<LifecycleEvent>>;
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

    pub async fn events_after_bounded(
        &self,
        task_id: &str,
        after_sequence: i64,
        limit: usize,
    ) -> Result<Vec<LifecycleEvent>, LifecycleError> {
        let mut events = self.events_after(task_id, after_sequence).await?;
        events.truncate(limit.max(1));
        Ok(events)
    }

    pub async fn snapshot(&self) -> LifecycleSnapshot {
        LifecycleSnapshot {
            profile: PROFILE.into(),
            records: self.records.lock().await.values().cloned().collect(),
        }
    }

    pub async fn restore(&self, snapshot: LifecycleSnapshot) -> Result<(), LifecycleError> {
        if snapshot.profile != PROFILE {
            return Err(LifecycleError::Conflict(
                "unsupported lifecycle snapshot profile".into(),
            ));
        }
        let mut restored = HashMap::new();
        for record in snapshot.records {
            if record.events.is_empty()
                || record.events.iter().enumerate().any(|(index, event)| {
                    event.sequence != record.events[0].sequence + index as u64
                })
            {
                return Err(LifecycleError::Conflict(
                    "invalid lifecycle snapshot sequence".into(),
                ));
            }
            restored.insert(record.task_id.clone(), record);
        }
        *self.records.lock().await = restored;
        Ok(())
    }
}

impl LifecyclePersistence for LifecycleStore {
    fn submit<'a>(
        &'a self,
        task_id: &'a str,
        idempotency_key: &'a str,
        request_digest: &'a str,
    ) -> LifecycleFuture<'a, (LifecycleRecord, bool)> {
        Box::pin(LifecycleStore::submit(
            self,
            task_id,
            idempotency_key,
            request_digest,
        ))
    }

    fn status<'a>(&'a self, task_id: &'a str) -> LifecycleFuture<'a, LifecycleRecord> {
        Box::pin(LifecycleStore::status(self, task_id))
    }

    fn transition<'a>(
        &'a self,
        task_id: &'a str,
        state: &'a str,
        detail: Value,
    ) -> LifecycleFuture<'a, LifecycleEvent> {
        Box::pin(LifecycleStore::transition(self, task_id, state, detail))
    }

    fn cancel<'a>(&'a self, task_id: &'a str) -> LifecycleFuture<'a, LifecycleRecord> {
        Box::pin(LifecycleStore::cancel(self, task_id))
    }

    fn events_after<'a>(
        &'a self,
        task_id: &'a str,
        after_sequence: i64,
    ) -> LifecycleFuture<'a, Vec<LifecycleEvent>> {
        Box::pin(LifecycleStore::events_after(self, task_id, after_sequence))
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn terminal(state: &str) -> bool {
    matches!(
        state,
        "rejected" | "completed" | "failed" | "cancelled" | "expired"
    )
}

pub(crate) fn legal_transition(from: &str, to: &str) -> bool {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleOperation {
    Submit,
    Status,
    Observe,
    Cancel,
}

#[derive(Clone, Debug)]
pub struct LifecycleAuthorizationRequest {
    pub credential: Option<String>,
    pub operation: LifecycleOperation,
    pub task_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleAuthorizationDecision {
    pub authenticated: bool,
    pub allowed: bool,
    pub conceal_task: bool,
}

impl LifecycleAuthorizationDecision {
    pub fn allowed() -> Self {
        Self {
            authenticated: true,
            allowed: true,
            conceal_task: false,
        }
    }
}

pub type LifecycleAuthorizer =
    Arc<dyn Fn(&LifecycleAuthorizationRequest) -> LifecycleAuthorizationDecision + Send + Sync>;

#[derive(Clone)]
struct HttpState {
    store: Arc<dyn LifecyclePersistence>,
    authorizer: LifecycleAuthorizer,
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

fn authorize(
    headers: &HeaderMap,
    state: &HttpState,
    operation: LifecycleOperation,
    task_id: &str,
) -> Result<(), StatusCode> {
    let request = LifecycleAuthorizationRequest {
        credential: headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        operation,
        task_id: task_id.to_owned(),
    };
    let decision = (state.authorizer)(&request);
    if decision.allowed && decision.authenticated {
        Ok(())
    } else if !decision.authenticated {
        Err(StatusCode::UNAUTHORIZED)
    } else if decision.conceal_task {
        Err(StatusCode::NOT_FOUND)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
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
        LifecycleError::Storage(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code": "lifecycle_storage_error", "message": message})),
        ).into_response(),
    }
}

async fn submit_http(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<SubmitRequest>,
) -> Response {
    if let Err(status) = authorize(&headers, &state, LifecycleOperation::Submit, &body.task_id) {
        return status.into_response();
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
    if let Err(status) = authorize(&headers, &state, LifecycleOperation::Status, &task_id) {
        return status.into_response();
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
    if let Err(status) = authorize(&headers, &state, LifecycleOperation::Observe, &task_id) {
        return status.into_response();
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
    if let Err(status) = authorize(&headers, &state, LifecycleOperation::Cancel, &task_id) {
        return status.into_response();
    }
    match state.store.cancel(&task_id).await {
        Ok(record) => Json(record_json(&record)).into_response(),
        Err(error) => lifecycle_error(error),
    }
}

/// Build the draft HTTP binding with the compatibility/test shared token.
pub fn lifecycle_router(store: LifecycleStore, bearer_token: impl Into<String>) -> Router {
    lifecycle_router_with_persistence(Arc::new(store), bearer_token)
}

/// Build the draft HTTP binding with a shared-token compatibility authorizer.
pub fn lifecycle_router_with_persistence(
    store: Arc<dyn LifecyclePersistence>,
    bearer_token: impl Into<String>,
) -> Router {
    let expected = format!("Bearer {}", bearer_token.into());
    let authorizer: LifecycleAuthorizer = Arc::new(move |request| {
        let valid = request.credential.as_deref() == Some(expected.as_str());
        LifecycleAuthorizationDecision {
            authenticated: valid,
            allowed: valid,
            conceal_task: false,
        }
    });
    lifecycle_router_with_authorizer(store, authorizer)
}

/// Build the explicitly mounted draft binding with operation-level authorization.
pub fn lifecycle_router_with_authorizer(
    store: Arc<dyn LifecyclePersistence>,
    authorizer: LifecycleAuthorizer,
) -> Router {
    let state = HttpState { store, authorizer };
    Router::new()
        .route("/v1/tasks", post(submit_http))
        .route("/v1/tasks/:task_id", get(status_http))
        .route("/v1/tasks/:task_id/events", get(observe_http))
        .route("/v1/tasks/:task_id/cancel", post(cancel_http))
        .with_state(state)
}
