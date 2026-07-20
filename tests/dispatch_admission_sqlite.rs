#![cfg(feature = "dispatch-admission-sqlite")]

use iicp_client::dispatch_admission::{
    evaluate_dispatch_admission, DispatchAdmissionClaim, DispatchAdmissionStore,
};
use iicp_client::dispatch_admission_sqlite::SqliteDispatchAdmissionStore;
use rusqlite::{params, Connection, TransactionBehavior};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::{Command, Stdio},
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../parity/dispatch-admission-v2.json")).unwrap()
}

fn claim(raw: &Value) -> DispatchAdmissionClaim {
    serde_json::from_value(raw.clone()).unwrap()
}

fn temp(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("iicp-admission-{name}-{}", uuid::Uuid::new_v4()));
    let path = root.join("admission.sqlite3");
    (root, path)
}

async fn run_case(store: &SqliteDispatchAdmissionStore, case: &Value) -> &'static str {
    let request = claim(&case["claim"]);
    for prior in case["prior"].as_array().into_iter().flatten() {
        let result = evaluate_dispatch_admission(
            store,
            &request,
            &request.provider_id,
            &request.intent,
            prior["now"]
                .as_u64()
                .unwrap_or(case["now"].as_u64().unwrap()),
            true,
            0,
        )
        .await;
        assert!(result.accepted);
        if let Some(state) = prior["terminal_state"].as_str() {
            store
                .transition(&request.jti, state, case["now"].as_u64().unwrap())
                .await
                .unwrap();
        }
    }
    let reopened;
    let selected: &dyn DispatchAdmissionStore = if case["reopen"].as_bool() == Some(true) {
        reopened = SqliteDispatchAdmissionStore::open(store.path()).unwrap();
        &reopened
    } else {
        store
    };
    evaluate_dispatch_admission(
        selected,
        &request,
        case["expected_provider_id"].as_str().unwrap(),
        case["expected_intent"].as_str().unwrap(),
        case["now"].as_u64().unwrap(),
        case["trust_verified"].as_bool().unwrap_or(true),
        fixture()["defaults"]["clock_skew_s"].as_u64().unwrap(),
    )
    .await
    .code
}

#[tokio::test]
async fn shared_admission_fixture() {
    let data = fixture();
    for case in data["cases"].as_array().unwrap() {
        let (root, path) = temp(case["id"].as_str().unwrap());
        let store = SqliteDispatchAdmissionStore::open(&path).unwrap();
        assert_eq!(
            run_case(&store, case).await,
            case["expected"].as_str().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn dispatch_admission_process_worker() {
    let Some(path) = std::env::var_os("IICP_ADMISSION_WORKER_PATH") else {
        return;
    };
    let raw = fixture()["cases"][0]["claim"].clone();
    let store = SqliteDispatchAdmissionStore::open(path).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let decision = runtime.block_on(evaluate_dispatch_admission(
        &store,
        &claim(&raw),
        raw["provider_id"].as_str().unwrap(),
        raw["intent"].as_str().unwrap(),
        1_700_000_000,
        true,
        0,
    ));
    println!("ADMISSION_RESULT={}", decision.code);
}

#[test]
fn two_process_consume_has_one_durable_winner() {
    let (root, path) = temp("multiprocess");
    SqliteDispatchAdmissionStore::open(&path).unwrap();
    let executable = std::env::current_exe().unwrap();
    let children = (0..2)
        .map(|_| {
            Command::new(&executable)
                .args([
                    "--exact",
                    "dispatch_admission_process_worker",
                    "--nocapture",
                ])
                .env("IICP_ADMISSION_WORKER_PATH", &path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    let mut outcomes = outputs
        .iter()
        .map(|output| {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("ADMISSION_RESULT=accepted") {
                "accepted"
            } else {
                "reject_replay"
            }
        })
        .collect::<Vec<_>>();
    outcomes.sort_unstable();
    assert_eq!(outcomes, ["accepted", "reject_replay"]);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn crash_boundaries_and_bounded_cleanup() {
    let (root, path) = temp("crash");
    let store = SqliteDispatchAdmissionStore::open(&path).unwrap();
    let raw = fixture()["cases"][0]["claim"].clone();

    let mut db = Connection::open(&path).unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "INSERT INTO dispatch_admissions VALUES(?1,'sha256:provider','sha256:intent','accepted',?2,1,1)",
        params![raw["jti"].as_str().unwrap(), raw["expires_at"].as_u64().unwrap()],
    ).unwrap();
    tx.rollback().unwrap();
    assert_eq!(run_case(&store, &fixture()["cases"][0]).await, "accepted");
    let record = store.lookup(raw["jti"].as_str().unwrap()).unwrap().unwrap();
    assert_eq!(
        record.provider_digest,
        format!(
            "sha256:{:x}",
            Sha256::digest(raw["provider_id"].as_str().unwrap().as_bytes())
        )
    );
    assert_eq!(
        record.intent_digest,
        format!(
            "sha256:{:x}",
            Sha256::digest(raw["intent"].as_str().unwrap().as_bytes())
        )
    );
    let durable_bytes = fs::read(&path).unwrap();
    assert!(!durable_bytes
        .windows(b"provider-a".len())
        .any(|window| window == b"provider-a"));
    assert!(!durable_bytes
        .windows(b"urn:iicp:intent".len())
        .any(|window| window == b"urn:iicp:intent"));
    assert_eq!(
        run_case(
            &SqliteDispatchAdmissionStore::open(&path).unwrap(),
            &fixture()["cases"][1]
        )
        .await,
        "reject_replay"
    );

    for index in 0..2 {
        let mut value = raw.clone();
        value["jti"] = format!("cleanup-ticket-{index:02}").into();
        value["not_before"] = 0.into();
        value["expires_at"] = 10.into();
        let candidate = claim(&value);
        assert!(
            evaluate_dispatch_admission(
                &store,
                &candidate,
                &candidate.provider_id,
                &candidate.intent,
                1,
                true,
                0
            )
            .await
            .accepted
        );
    }
    assert_eq!(store.cleanup(200, 100, 1).unwrap(), 1);
    assert_eq!(store.cleanup(200, 100, 1).unwrap(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn locked_and_corrupt_store_fail_closed() {
    let (root, path) = temp("locked");
    let store = SqliteDispatchAdmissionStore::with_busy_timeout(&path, Duration::ZERO).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let worker_path = path.clone();
    let worker_barrier = Arc::clone(&barrier);
    let holder = thread::spawn(move || {
        let mut db = Connection::open(worker_path).unwrap();
        let _tx = db
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .unwrap();
        worker_barrier.wait();
        thread::sleep(Duration::from_millis(200));
    });
    barrier.wait();
    let raw = fixture()["cases"][0]["claim"].clone();
    let decision = evaluate_dispatch_admission(
        &store,
        &claim(&raw),
        "provider-a",
        "urn:iicp:intent:llm:chat:v1",
        1_700_000_000,
        true,
        0,
    )
    .await;
    assert_eq!(decision.code, "reject_store_unavailable");
    holder.join().unwrap();

    let corrupt = root.join("corrupt.sqlite3");
    fs::write(&corrupt, b"not sqlite").unwrap();
    assert!(SqliteDispatchAdmissionStore::open(corrupt).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn database_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (root, path) = temp("permissions");
    SqliteDispatchAdmissionStore::open(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
    fs::remove_dir_all(root).unwrap();
}
