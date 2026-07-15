use iicp_client::service_lifecycle::{lifecycle_router, LifecycleError, LifecycleStore};
use serde_json::{json, Value};

#[tokio::test]
async fn lifecycle_fixture_transitions_and_alias_are_portable() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/service-lifecycle-v1.json")).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        if !matches!(vector["kind"].as_str(), Some("valid" | "alias")) {
            continue;
        }
        let id = vector["id"].as_str().unwrap();
        let store = LifecycleStore::new(256, 3_600_000);
        store.submit(id, id, "sha256:test").await.unwrap();
        for event in vector["events"].as_array().unwrap().iter().skip(1) {
            store
                .transition(id, event[0].as_str().unwrap(), Value::Null)
                .await
                .unwrap();
        }
        let expected = if vector["kind"] == "alias" {
            "expired"
        } else {
            vector["events"].as_array().unwrap().last().unwrap()[0]
                .as_str()
                .unwrap()
        };
        assert_eq!(store.status(id).await.unwrap().state, expected);
    }
}

#[tokio::test]
async fn opt_in_http_adapter_resumes_without_duplicate_execution() {
    let store = LifecycleStore::new(8, 3_600_000);
    let app = lifecycle_router(store.clone(), "test-token");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{address}/v1/tasks");
    let body = json!({"task_id":"task-1","idempotency_key":"key-1","request_digest":"sha256:one"});

    assert_eq!(
        client.post(&url).json(&body).send().await.unwrap().status(),
        401
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth("test-token")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth("test-token")
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let reused_key =
        json!({"task_id":"task-2","idempotency_key":"key-1","request_digest":"sha256:one"});
    assert_eq!(
        client
            .post(&url)
            .bearer_auth("test-token")
            .json(&reused_key)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert!(matches!(
        store.submit("task-1", "key-1", "sha256:different").await,
        Err(LifecycleError::Conflict(_))
    ));

    store
        .transition("task-1", "running", Value::Null)
        .await
        .unwrap();
    store
        .transition(
            "task-1",
            "streaming",
            json!({"progress":{"completed_units":1,"total_units":2}}),
        )
        .await
        .unwrap();
    let first = client
        .get(format!("{url}/task-1/events?after_sequence=0"))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let first_sequences = first
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["sequence"]
                .as_u64()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(first_sequences, vec![1, 2]);

    store
        .transition("task-1", "completed", json!({"result_ref":"opaque:test"}))
        .await
        .unwrap();
    let resumed = client
        .get(format!("{url}/task-1/events?after_sequence=2"))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(resumed.trim()).unwrap()["state"],
        "completed"
    );
    let terminal: Value = client
        .post(format!("{url}/task-1/cancel"))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(terminal["state"], "completed");
    server.abort();
}

#[tokio::test]
async fn replay_window_expires_without_starting_a_second_execution() {
    let store = LifecycleStore::new(2, 3_600_000);
    store
        .submit("task-window", "key-window", "sha256:window")
        .await
        .unwrap();
    store
        .transition("task-window", "running", Value::Null)
        .await
        .unwrap();
    store
        .transition("task-window", "streaming", Value::Null)
        .await
        .unwrap();
    store
        .transition("task-window", "completed", Value::Null)
        .await
        .unwrap();
    assert!(matches!(
        store.events_after("task-window", 0).await,
        Err(LifecycleError::ResumeUnavailable { .. })
    ));
}
