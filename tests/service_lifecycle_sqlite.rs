#![cfg(feature = "lifecycle-sqlite")]

use iicp_client::{
    service_lifecycle::{LifecycleError, LifecyclePersistence},
    service_lifecycle_sqlite::SqliteLifecyclePersistence,
};
use rusqlite::{Connection, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

fn test_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "iicp-lifecycle-{name}-{}.sqlite3",
        uuid::Uuid::new_v4()
    ))
}

#[test]
fn lifecycle_sqlite_worker() {
    let Ok(action) = std::env::var("IICP_LIFECYCLE_WORKER") else {
        return;
    };
    let path = std::env::var("IICP_LIFECYCLE_DB").unwrap();
    if action == "crash-mid-transition" {
        let mut db = Connection::open(path).unwrap();
        db.pragma_update(None, "journal_mode", "WAL").unwrap();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let sequence: u64 = tx
            .query_row(
                "SELECT latest_sequence FROM lifecycle_tasks WHERE task_id='shared-task'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        tx.execute(
            "UPDATE lifecycle_tasks SET state='streaming',latest_sequence=?1 WHERE task_id='shared-task'",
            [sequence + 1],
        )
        .unwrap();
        std::process::abort();
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let store = SqliteLifecyclePersistence::open(path, 3, 3_600_000).unwrap();
    let state = if action == "complete" {
        "completed"
    } else {
        "failed"
    };
    let detail = if state == "completed" {
        json!({"outcome": "completed"})
    } else {
        json!({"reason_code": "worker_failed"})
    };
    let outcome = runtime.block_on(store.transition("shared-task", state, detail));
    match outcome {
        Ok(_) => {}
        Err(LifecycleError::Conflict(_)) => std::process::exit(2),
        Err(error) => panic!("unexpected worker error: {error:?}"),
    }
}

fn worker(action: &str, path: &PathBuf) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lifecycle_sqlite_worker", "--nocapture"])
        .env("IICP_LIFECYCLE_WORKER", action)
        .env("IICP_LIFECYCLE_DB", path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[tokio::test]
async fn sqlite_is_opt_in_content_free_and_router_compatible() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/service-lifecycle-persistence-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["fixture_version"], "0.1.0-draft");
    assert_eq!(fixture["vectors"].as_array().unwrap().len(), 10);
    let path = test_path("basic");
    let store = SqliteLifecyclePersistence::open(&path, 3, 3_600_000).unwrap();
    let persistence: Arc<dyn LifecyclePersistence> = Arc::new(store.clone());
    let (record, created) = persistence
        .submit("durable", "idem-durable", "sha256:request")
        .await
        .unwrap();
    assert!(created);
    assert_eq!(record.state, "accepted");
    assert!(
        !persistence
            .submit("durable", "idem-durable", "sha256:request")
            .await
            .unwrap()
            .1
    );
    persistence
        .transition("durable", "running", Value::Null)
        .await
        .unwrap();
    persistence
        .transition(
            "durable",
            "streaming",
            json!({
                "event_id": "event-2",
                "progress": {"completed_units": 1, "total_units": 2, "unit": "chunks"}
            }),
        )
        .await
        .unwrap();
    let restarted = SqliteLifecyclePersistence::open(&path, 3, 3_600_000).unwrap();
    assert_eq!(
        restarted.status("durable").await.unwrap().state,
        "streaming"
    );
    assert!(matches!(
        restarted
            .transition(
                "durable",
                "completed",
                json!({"response": "must-not-persist"})
            )
            .await,
        Err(LifecycleError::Conflict(_))
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let database = std::fs::read(&path).unwrap();
    let lowered = String::from_utf8_lossy(&database).to_ascii_lowercase();
    for forbidden in [
        "prompt",
        "response",
        "credential",
        "endpoint",
        "peer_topology",
    ] {
        assert!(!lowered.contains(forbidden));
    }
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sqlite_two_process_crash_recovery_and_single_terminal_winner() {
    let path = test_path("process");
    let store = SqliteLifecyclePersistence::open(&path, 3, 3_600_000).unwrap();
    store
        .submit("shared-task", "shared-idem", "sha256:shared")
        .await
        .unwrap();
    store
        .transition("shared-task", "running", Value::Null)
        .await
        .unwrap();

    let crashed = worker("crash-mid-transition", &path).wait().unwrap();
    assert!(!crashed.success());
    let recovered = SqliteLifecyclePersistence::open(&path, 3, 3_600_000).unwrap();
    let record = recovered.status("shared-task").await.unwrap();
    assert_eq!(record.state, "running");
    assert_eq!(record.latest_sequence(), 1);

    let first = worker("complete", &path);
    let second = worker("fail", &path);
    let mut outcomes = [
        first.wait_with_output().unwrap().status.code(),
        second.wait_with_output().unwrap().status.code(),
    ];
    outcomes.sort();
    assert_eq!(outcomes, [Some(0), Some(2)]);
    let terminal = SqliteLifecyclePersistence::open(&path, 3, 3_600_000)
        .unwrap()
        .status("shared-task")
        .await
        .unwrap();
    assert!(matches!(terminal.state.as_str(), "completed" | "failed"));
    assert_eq!(terminal.latest_sequence(), 2);
    assert_eq!(
        terminal
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn sqlite_bounded_replay_and_terminal_ttl() {
    let path = test_path("ttl");
    let store = SqliteLifecyclePersistence::open(&path, 2, 1_000).unwrap();
    store.submit("ttl", "idem-ttl", "digest").await.unwrap();
    store
        .transition("ttl", "running", Value::Null)
        .await
        .unwrap();
    store
        .transition("ttl", "streaming", Value::Null)
        .await
        .unwrap();
    store
        .transition(
            "ttl",
            "completed",
            json!({"receipt_digest": format!("sha256:{}", "a".repeat(64))}),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.events_after("ttl", 0).await,
        Err(LifecycleError::ResumeUnavailable { .. })
    ));

    let ttl_path = test_path("expiry");
    let expiring = SqliteLifecyclePersistence::open(&ttl_path, 2, 1).unwrap();
    expiring
        .submit("expiry", "idem-expiry", "digest")
        .await
        .unwrap();
    expiring
        .transition("expiry", "completed", Value::Null)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(matches!(
        expiring.status("expiry").await,
        Err(LifecycleError::UnknownTask)
    ));
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(ttl_path);
}

#[test]
fn sqlite_rejects_corrupt_schema_and_unusable_path() {
    let corrupt = test_path("corrupt");
    std::fs::write(&corrupt, b"not a sqlite database").unwrap();
    assert!(matches!(
        SqliteLifecyclePersistence::open(&corrupt, 2, 1_000),
        Err(LifecycleError::Storage(_))
    ));

    let blocker = test_path("not-a-directory");
    std::fs::write(&blocker, b"blocked").unwrap();
    assert!(matches!(
        SqliteLifecyclePersistence::open(blocker.join("lifecycle.sqlite3"), 2, 1_000),
        Err(LifecycleError::Storage(_))
    ));
    let _ = std::fs::remove_file(corrupt);
    let _ = std::fs::remove_file(blocker);
}
