// SPDX-License-Identifier: Apache-2.0
//! Opt-in SQLite implementation of provider-local dispatch admission.

use crate::dispatch_admission::{
    terminal, DispatchAdmissionClaim, DispatchAdmissionDecision, DispatchAdmissionError,
    DispatchAdmissionRecord, DispatchAdmissionStore,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug)]
pub struct SqliteDispatchAdmissionStore {
    path: PathBuf,
    busy_timeout: Duration,
}

impl SqliteDispatchAdmissionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DispatchAdmissionError> {
        Self::with_busy_timeout(path, Duration::from_secs(5))
    }

    pub fn with_busy_timeout(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, DispatchAdmissionError> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
            busy_timeout,
        };
        if let Some(parent) = store.path.parent() {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let db = store.connect()?;
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(storage)?;
        if !matches!(version, 0 | SCHEMA_VERSION) {
            return Err(DispatchAdmissionError::Storage(format!(
                "unsupported dispatch admission database version {version}"
            )));
        }
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS dispatch_admissions (
                jti TEXT PRIMARY KEY,
                provider_digest TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS dispatch_admissions_expiry ON dispatch_admissions(expires_at);
            PRAGMA user_version=1;",
        ).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o600))
                .map_err(storage)?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<Connection, DispatchAdmissionError> {
        let db = Connection::open(&self.path).map_err(storage)?;
        db.busy_timeout(self.busy_timeout).map_err(storage)?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        Ok(db)
    }

    fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<DispatchAdmissionRecord> {
        Ok(DispatchAdmissionRecord {
            jti: row.get(0)?,
            provider_digest: row.get(1)?,
            intent_digest: row.get(2)?,
            state: row.get(3)?,
            expires_at: row.get(4)?,
            consumed_at: row.get(5)?,
            updated_at: row.get(6)?,
        })
    }

    fn consume_sync(
        &self,
        claim: &DispatchAdmissionClaim,
        expected_provider_id: &str,
        expected_intent: &str,
        now: u64,
        clock_skew_s: u64,
    ) -> Result<DispatchAdmissionDecision, DispatchAdmissionError> {
        if claim.jti.len() < 16
            || claim.jti.len() > 256
            || !claim
                .jti
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
        {
            return Ok(DispatchAdmissionDecision::reject("reject_invalid_jti"));
        }
        if claim.provider_id != expected_provider_id {
            return Ok(DispatchAdmissionDecision::reject("reject_provider_binding"));
        }
        if claim.intent != expected_intent {
            return Ok(DispatchAdmissionDecision::reject("reject_intent_binding"));
        }
        if now.saturating_add(clock_skew_s) < claim.not_before {
            return Ok(DispatchAdmissionDecision::reject("reject_not_yet_valid"));
        }
        if now.saturating_sub(clock_skew_s) >= claim.expires_at {
            return Ok(DispatchAdmissionDecision::reject("reject_expired"));
        }

        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let existing = tx.query_row(
            "SELECT jti,provider_digest,intent_digest,state,expires_at,consumed_at,updated_at FROM dispatch_admissions WHERE jti=?1",
            [&claim.jti], Self::record,
        ).optional().map_err(storage)?;
        if let Some(record) = existing {
            tx.commit().map_err(storage)?;
            return Ok(DispatchAdmissionDecision {
                code: if terminal(&record.state) {
                    "reject_terminal"
                } else {
                    "reject_replay"
                },
                accepted: false,
                state: Some(record.state),
            });
        }
        let provider_digest = format!("sha256:{:x}", Sha256::digest(claim.provider_id.as_bytes()));
        let intent_digest = format!("sha256:{:x}", Sha256::digest(claim.intent.as_bytes()));
        tx.execute(
            "INSERT INTO dispatch_admissions VALUES(?1,?2,?3,'accepted',?4,?5,?5)",
            params![
                claim.jti,
                provider_digest,
                intent_digest,
                claim.expires_at,
                now
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(DispatchAdmissionDecision::accepted())
    }

    fn transition_sync(
        &self,
        jti: &str,
        state: &str,
        now: u64,
    ) -> Result<DispatchAdmissionRecord, DispatchAdmissionError> {
        if !terminal(state) {
            return Err(DispatchAdmissionError::Transition(state.into()));
        }
        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let existing = tx.query_row(
            "SELECT jti,provider_digest,intent_digest,state,expires_at,consumed_at,updated_at FROM dispatch_admissions WHERE jti=?1",
            [jti], Self::record,
        ).optional().map_err(storage)?.ok_or(DispatchAdmissionError::Unknown)?;
        if terminal(&existing.state) && existing.state != state {
            return Err(DispatchAdmissionError::Transition(format!(
                "already terminal as {}",
                existing.state
            )));
        }
        if existing.state != state {
            tx.execute(
                "UPDATE dispatch_admissions SET state=?1,updated_at=?2 WHERE jti=?3",
                params![state, now, jti],
            )
            .map_err(storage)?;
        }
        let record = tx.query_row(
            "SELECT jti,provider_digest,intent_digest,state,expires_at,consumed_at,updated_at FROM dispatch_admissions WHERE jti=?1",
            [jti], Self::record,
        ).map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(record)
    }
}

impl DispatchAdmissionStore for SqliteDispatchAdmissionStore {
    fn consume<'a>(
        &'a self,
        claim: &'a DispatchAdmissionClaim,
        provider: &'a str,
        intent: &'a str,
        now: u64,
        skew: u64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<DispatchAdmissionDecision, DispatchAdmissionError>,
                > + Send
                + 'a,
        >,
    > {
        let store = self.clone();
        let claim = claim.clone();
        let provider = provider.to_owned();
        let intent = intent.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                store.consume_sync(&claim, &provider, &intent, now, skew)
            })
            .await
            .map_err(storage)?
        })
    }

    fn transition<'a>(
        &'a self,
        jti: &'a str,
        state: &'a str,
        now: u64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<DispatchAdmissionRecord, DispatchAdmissionError>,
                > + Send
                + 'a,
        >,
    > {
        let store = self.clone();
        let jti = jti.to_owned();
        let state = state.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.transition_sync(&jti, &state, now))
                .await
                .map_err(storage)?
        })
    }

    fn cleanup(
        &self,
        now: u64,
        retention_s: u64,
        limit: usize,
    ) -> Result<usize, DispatchAdmissionError> {
        let cutoff = now.saturating_sub(retention_s);
        let mut db = self.connect()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let deleted = tx.execute(
            "DELETE FROM dispatch_admissions WHERE jti IN (SELECT jti FROM dispatch_admissions WHERE expires_at < ?1 ORDER BY expires_at LIMIT ?2)",
            params![cutoff, limit.max(1)],
        ).map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(deleted)
    }

    fn lookup(&self, jti: &str) -> Result<Option<DispatchAdmissionRecord>, DispatchAdmissionError> {
        self.connect()?.query_row(
            "SELECT jti,provider_digest,intent_digest,state,expires_at,consumed_at,updated_at FROM dispatch_admissions WHERE jti=?1",
            [jti], Self::record,
        ).optional().map_err(storage)
    }
}

fn storage(error: impl std::fmt::Display) -> DispatchAdmissionError {
    DispatchAdmissionError::Storage(error.to_string())
}
