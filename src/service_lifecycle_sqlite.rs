// SPDX-License-Identifier: Apache-2.0
//! Opt-in single-host SQLite persistence for the draft lifecycle profile.
//!
//! The adapter coordinates local processes through transactional state/event
//! updates. It is not a distributed consensus store and does not protect
//! against restoration of the complete database.

use crate::service_lifecycle::{
    legal_transition, now_ms, terminal, LifecycleError, LifecycleEvent, LifecycleFuture,
    LifecyclePersistence, LifecycleRecord,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{Map, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug)]
pub struct SqliteLifecyclePersistence {
    path: PathBuf,
    max_events: usize,
    terminal_status_ttl_ms: u64,
}

impl SqliteLifecyclePersistence {
    pub fn open(
        path: impl AsRef<Path>,
        max_events: usize,
        terminal_status_ttl_ms: u64,
    ) -> Result<Self, LifecycleError> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
            max_events: max_events.max(2),
            terminal_status_ttl_ms,
        };
        if let Some(parent) = store.path.parent() {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let db = store.connect()?;
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(storage)?;
        if !matches!(version, 0 | SCHEMA_VERSION) {
            return Err(LifecycleError::Storage(format!(
                "unsupported lifecycle database version {version}"
            )));
        }
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS lifecycle_tasks (
                task_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                latest_sequence INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lifecycle_events (
                task_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                state TEXT NOT NULL,
                is_final INTEGER NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                detail_json BLOB NOT NULL,
                PRIMARY KEY(task_id, sequence),
                FOREIGN KEY(task_id) REFERENCES lifecycle_tasks(task_id) ON DELETE CASCADE
            );
            PRAGMA user_version=1;",
        )
        .map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o600))
                .map_err(storage)?;
        }
        Ok(store)
    }

    fn connect(&self) -> Result<Connection, LifecycleError> {
        let db = Connection::open(&self.path).map_err(storage)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(storage)?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        db.pragma_update(None, "foreign_keys", "ON")
            .map_err(storage)?;
        Ok(db)
    }

    fn load_record(db: &Connection, task_id: &str) -> Result<LifecycleRecord, LifecycleError> {
        let task = db
            .query_row(
                "SELECT task_id,idempotency_key,request_digest,state,updated_at_ms FROM lifecycle_tasks WHERE task_id=?1",
                [task_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or(LifecycleError::UnknownTask)?;
        let mut statement = db
            .prepare(
                "SELECT task_id,sequence,state,is_final,observed_at_ms,detail_json
                 FROM lifecycle_events WHERE task_id=?1 ORDER BY sequence",
            )
            .map_err(storage)?;
        let events = statement
            .query_map([task_id], |row| {
                let detail: Vec<u8> = row.get(5)?;
                let detail = serde_json::from_slice(&detail).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        detail.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?;
                Ok(LifecycleEvent {
                    task_id: row.get(0)?,
                    sequence: row.get(1)?,
                    state: row.get(2)?,
                    is_final: row.get::<_, i64>(3)? != 0,
                    observed_at_ms: row.get(4)?,
                    detail,
                })
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        if events.is_empty() {
            return Err(LifecycleError::Storage(
                "task has no lifecycle events".into(),
            ));
        }
        Ok(LifecycleRecord {
            task_id: task.0,
            idempotency_key: task.1,
            request_digest: task.2,
            state: task.3,
            events,
            updated_at_ms: task.4,
        })
    }

    fn submit_sync(
        &self,
        task_id: &str,
        idempotency_key: &str,
        request_digest: &str,
    ) -> Result<(LifecycleRecord, bool), LifecycleError> {
        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let existing = tx
            .query_row(
                "SELECT task_id,idempotency_key,request_digest FROM lifecycle_tasks
                 WHERE task_id=?1 OR idempotency_key=?2",
                params![task_id, idempotency_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        if let Some(existing) = existing {
            if existing
                != (
                    task_id.to_owned(),
                    idempotency_key.to_owned(),
                    request_digest.to_owned(),
                )
            {
                return Err(LifecycleError::Conflict(
                    "task or idempotency identifier reused for different content".into(),
                ));
            }
            let record = Self::load_record(&tx, task_id)?;
            tx.commit().map_err(storage)?;
            return Ok((record, false));
        }
        let now = now_ms();
        tx.execute(
            "INSERT INTO lifecycle_tasks VALUES(?1,?2,?3,'accepted',0,?4)",
            params![task_id, idempotency_key, request_digest, now],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO lifecycle_events VALUES(?1,0,'accepted',0,?2,?3)",
            params![task_id, now, b"{}".as_slice()],
        )
        .map_err(storage)?;
        let record = Self::load_record(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok((record, true))
    }

    fn status_sync(&self, task_id: &str) -> Result<LifecycleRecord, LifecycleError> {
        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row = tx
            .query_row(
                "SELECT state,updated_at_ms FROM lifecycle_tasks WHERE task_id=?1",
                [task_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or(LifecycleError::UnknownTask)?;
        if terminal(&row.0) && now_ms().saturating_sub(row.1) > self.terminal_status_ttl_ms {
            tx.execute("DELETE FROM lifecycle_tasks WHERE task_id=?1", [task_id])
                .map_err(storage)?;
            tx.commit().map_err(storage)?;
            return Err(LifecycleError::UnknownTask);
        }
        let record = Self::load_record(&tx, task_id)?;
        tx.commit().map_err(storage)?;
        Ok(record)
    }

    fn transition_sync(
        &self,
        task_id: &str,
        requested_state: &str,
        detail: Value,
    ) -> Result<LifecycleEvent, LifecycleError> {
        let state = if requested_state == "timed_out" {
            "expired"
        } else {
            requested_state
        };
        let detail = content_free_detail(detail)?;
        let detail_json = serde_json::to_vec(&detail).map_err(storage)?;
        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current = tx
            .query_row(
                "SELECT state,latest_sequence FROM lifecycle_tasks WHERE task_id=?1",
                [task_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or(LifecycleError::UnknownTask)?;
        if !legal_transition(&current.0, state) {
            return Err(LifecycleError::Conflict(format!(
                "illegal transition {} -> {state}",
                current.0
            )));
        }
        let sequence = current.1 + 1;
        let now = now_ms();
        tx.execute(
            "UPDATE lifecycle_tasks SET state=?1,latest_sequence=?2,updated_at_ms=?3 WHERE task_id=?4",
            params![state, sequence, now, task_id],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO lifecycle_events VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                task_id,
                sequence,
                state,
                i64::from(terminal(state)),
                now,
                detail_json
            ],
        )
        .map_err(storage)?;
        let cutoff = sequence.saturating_sub(self.max_events as u64 - 1);
        tx.execute(
            "DELETE FROM lifecycle_events WHERE task_id=?1 AND sequence<?2",
            params![task_id, cutoff],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(LifecycleEvent {
            task_id: task_id.into(),
            sequence,
            state: state.into(),
            is_final: terminal(state),
            observed_at_ms: now,
            detail,
        })
    }

    fn events_after_sync(
        &self,
        task_id: &str,
        after_sequence: i64,
    ) -> Result<Vec<LifecycleEvent>, LifecycleError> {
        let record = self.status_sync(task_id)?;
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

impl LifecyclePersistence for SqliteLifecyclePersistence {
    fn submit<'a>(
        &'a self,
        task_id: &'a str,
        idempotency_key: &'a str,
        request_digest: &'a str,
    ) -> LifecycleFuture<'a, (LifecycleRecord, bool)> {
        let store = self.clone();
        let task_id = task_id.to_owned();
        let idempotency_key = idempotency_key.to_owned();
        let request_digest = request_digest.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store.submit_sync(&task_id, &idempotency_key, &request_digest)
            })
            .await
            .map_err(storage)?
        })
    }

    fn status<'a>(&'a self, task_id: &'a str) -> LifecycleFuture<'a, LifecycleRecord> {
        let store = self.clone();
        let task_id = task_id.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.status_sync(&task_id))
                .await
                .map_err(storage)?
        })
    }

    fn transition<'a>(
        &'a self,
        task_id: &'a str,
        state: &'a str,
        detail: Value,
    ) -> LifecycleFuture<'a, LifecycleEvent> {
        let store = self.clone();
        let task_id = task_id.to_owned();
        let state = state.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.transition_sync(&task_id, &state, detail))
                .await
                .map_err(storage)?
        })
    }

    fn cancel<'a>(&'a self, task_id: &'a str) -> LifecycleFuture<'a, LifecycleRecord> {
        let store = self.clone();
        let task_id = task_id.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let current = store.status_sync(&task_id)?;
                if !terminal(&current.state) {
                    store.transition_sync(
                        &task_id,
                        "cancelled",
                        serde_json::json!({"outcome": "cancelled"}),
                    )?;
                }
                store.status_sync(&task_id)
            })
            .await
            .map_err(storage)?
        })
    }

    fn events_after<'a>(
        &'a self,
        task_id: &'a str,
        after_sequence: i64,
    ) -> LifecycleFuture<'a, Vec<LifecycleEvent>> {
        let store = self.clone();
        let task_id = task_id.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.events_after_sync(&task_id, after_sequence))
                .await
                .map_err(storage)?
        })
    }
}

fn content_free_detail(detail: Value) -> Result<Value, LifecycleError> {
    if detail.is_null() {
        return Ok(Value::Object(Map::new()));
    }
    let object = detail.as_object().ok_or_else(|| {
        LifecycleError::Conflict("durable lifecycle detail must be an object".into())
    })?;
    let mut result = Map::new();
    for (key, value) in object {
        match key.as_str() {
            "progress" => {
                let progress = value.as_object().ok_or_else(|| {
                    LifecycleError::Conflict("invalid durable lifecycle progress".into())
                })?;
                if progress
                    .keys()
                    .any(|key| !matches!(key.as_str(), "completed_units" | "total_units" | "unit"))
                {
                    return Err(LifecycleError::Conflict(
                        "invalid durable lifecycle progress".into(),
                    ));
                }
                let completed = progress
                    .get("completed_units")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        LifecycleError::Conflict("invalid durable lifecycle progress counts".into())
                    })?;
                let total = progress
                    .get("total_units")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        LifecycleError::Conflict("invalid durable lifecycle progress counts".into())
                    })?;
                if total < completed {
                    return Err(LifecycleError::Conflict(
                        "invalid durable lifecycle progress counts".into(),
                    ));
                }
                if let Some(unit) = progress.get("unit") {
                    safe_token(unit.as_str().ok_or_else(|| {
                        LifecycleError::Conflict("invalid progress unit".into())
                    })?)?;
                }
                result.insert(key.clone(), value.clone());
            }
            "receipt_digest" | "checkpoint_digest" => {
                let digest = value
                    .as_str()
                    .ok_or_else(|| LifecycleError::Conflict(format!("invalid {key}")))?;
                let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
                if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(LifecycleError::Conflict(format!("invalid {key}")));
                }
                result.insert(key.clone(), Value::String(digest.to_ascii_lowercase()));
            }
            "event_id" | "reason_code" | "outcome" => {
                safe_token(value.as_str().ok_or_else(|| {
                    LifecycleError::Conflict(format!("invalid durable lifecycle {key}"))
                })?)?;
                result.insert(key.clone(), value.clone());
            }
            _ => {
                return Err(LifecycleError::Conflict(format!(
                    "durable lifecycle detail contains unsupported field: {key}"
                )));
            }
        }
    }
    Ok(Value::Object(result))
}

fn safe_token(value: &str) -> Result<(), LifecycleError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(LifecycleError::Conflict(
            "invalid durable lifecycle token".into(),
        ));
    }
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> LifecycleError {
    LifecycleError::Storage(error.to_string())
}
