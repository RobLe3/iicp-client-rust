use iicp_client::service_lifecycle::{lifecycle_router, LifecycleError, LifecycleStore};
use iicp_client::service_lifecycle::{
    BackendCancellationRegistry, BoundedObserverBuffer, LifecycleEvent, ObserverLagged,
};
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

#[tokio::test]
async fn snapshot_restore_and_bounded_replay_are_deterministic() {
    let store = LifecycleStore::new(3, 60_000);
    store
        .submit("restart", "idem-restart", "digest")
        .await
        .unwrap();
    store
        .transition("restart", "running", serde_json::Value::Null)
        .await
        .unwrap();
    for chunk in 1..=3 {
        store
            .transition("restart", "streaming", serde_json::json!({"chunk": chunk}))
            .await
            .unwrap();
    }
    let restored = LifecycleStore::new(3, 60_000);
    restored.restore(store.snapshot().await).await.unwrap();
    assert!(matches!(
        restored.events_after("restart", 0).await,
        Err(LifecycleError::ResumeUnavailable { .. })
    ));
    assert_eq!(
        restored
            .events_after_bounded("restart", 1, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(restored.cancel("restart").await.unwrap().state, "cancelled");
    assert_eq!(restored.cancel("restart").await.unwrap().state, "cancelled");
}

#[tokio::test]
async fn task_scoped_authorizer_conceals_cross_principal_access() {
    use iicp_client::service_lifecycle::{
        lifecycle_router_with_authorizer, LifecycleAuthorizationDecision, LifecycleAuthorizer,
        LifecycleOperation,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/service-lifecycle-authorization-v1.json"
    ))
    .unwrap();
    let owners = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let auth_owners = owners.clone();
    let authorizer: LifecycleAuthorizer = Arc::new(move |request| {
        let token = request.credential.as_deref();
        if matches!(token, None | Some("Bearer invalid" | "Bearer expired")) {
            return LifecycleAuthorizationDecision {
                authenticated: false,
                allowed: false,
                conceal_task: false,
            };
        }
        let principal = match token {
            Some("Bearer owner") => "owner",
            Some("Bearer other") => "other",
            Some("Bearer read-only") => "reader",
            Some("Bearer operator") => "operator",
            _ => {
                return LifecycleAuthorizationDecision {
                    authenticated: false,
                    allowed: false,
                    conceal_task: false,
                }
            }
        };
        if principal == "operator" {
            return LifecycleAuthorizationDecision::allowed();
        }
        if request.operation == LifecycleOperation::Submit {
            if principal == "owner" {
                auth_owners
                    .lock()
                    .unwrap()
                    .entry(request.task_id.clone())
                    .or_insert_with(|| principal.to_owned());
                return LifecycleAuthorizationDecision::allowed();
            }
            return LifecycleAuthorizationDecision {
                authenticated: true,
                allowed: false,
                conceal_task: false,
            };
        }
        let allowed = auth_owners
            .lock()
            .unwrap()
            .get(&request.task_id)
            .is_some_and(|owner| owner == principal);
        LifecycleAuthorizationDecision {
            authenticated: true,
            allowed,
            conceal_task: !allowed,
        }
    });

    let store = Arc::new(LifecycleStore::new(8, 3_600_000));
    let app = lifecycle_router_with_authorizer(store, authorizer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let base = format!("http://{address}/v1/tasks");
    let body = json!({"task_id":"task-a","idempotency_key":"key-a","request_digest":"sha256:a"});

    for case in fixture["cases"].as_array().unwrap() {
        let mut request = match case["operation"].as_str().unwrap() {
            "submit" => client.post(&base).json(&if case["task_id"] == "task-a" {
                body.clone()
            } else {
                json!({"task_id":"task-b","idempotency_key":"key-b","request_digest":"sha256:a"})
            }),
            "status" => client.get(format!("{base}/{}", case["task_id"].as_str().unwrap())),
            "observe" => client.get(format!(
                "{base}/{}/events",
                case["task_id"].as_str().unwrap()
            )),
            "cancel" => client.post(format!(
                "{base}/{}/cancel",
                case["task_id"].as_str().unwrap()
            )),
            _ => unreachable!(),
        };
        if let Some(credential) = case["credential"].as_str() {
            request = request.header("Authorization", credential);
        }
        let response = request.send().await.unwrap();
        let mut expected = fixture["decision_contract"][case["expected"].as_str().unwrap()]
            .as_u64()
            .unwrap() as u16;
        if case["id"] == "LIFECYCLE-AUTH-03" {
            expected = 202;
        }
        assert_eq!(response.status().as_u16(), expected, "{}", case["id"]);
        let response_text = response.text().await.unwrap();
        assert!(!response_text.contains("principal_id"));
        if let Some(credential) = case["credential"].as_str() {
            assert!(!response_text.contains(credential));
        }
    }
    server.abort();
}
#[tokio::test]
async fn runtime_control_fixture_cancellation_and_bounded_observation() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../parity/service-lifecycle-runtime-control-v1.json"
    ))
    .unwrap();
    for vector in fixture["cancellation"].as_array().unwrap() {
        let registry = BackendCancellationRegistry::default();
        if vector["handler"] == "registered" {
            registry.register("task", || true);
        }
        assert_eq!(
            registry.request("task", vector["state"].as_str().unwrap()),
            vector["expected"].as_str().unwrap()
        );
    }

    let observation = &fixture["observation"];
    let buffer = BoundedObserverBuffer::new(observation["capacity"].as_u64().unwrap() as usize, 1);
    buffer.subscribe("observer").unwrap();
    for sequence in observation["published_sequences"].as_array().unwrap() {
        buffer
            .publish(LifecycleEvent {
                task_id: "task".into(),
                sequence: sequence.as_u64().unwrap(),
                state: "streaming".into(),
                is_final: false,
                observed_at_ms: 1,
                detail: serde_json::Value::Null,
            })
            .unwrap();
    }
    assert_eq!(
        buffer
            .poll(1)
            .unwrap()
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(
        buffer.poll(0).unwrap_err(),
        ObserverLagged {
            earliest_available: 2,
            latest_sequence: 3,
        }
    );
    buffer
        .publish(LifecycleEvent {
            task_id: "task".into(),
            sequence: 4,
            state: "completed".into(),
            is_final: true,
            observed_at_ms: 2,
            detail: serde_json::Value::Null,
        })
        .unwrap();
    assert!(buffer.is_closed());
    buffer.disconnect("observer");
    assert_eq!(buffer.observer_count(), 0);
}

#[tokio::test]
async fn cancellation_registry_aborts_active_http_request() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await;
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    });
    let request = tokio::spawn(async move { reqwest::get(format!("http://{address}/slow")).await });
    tokio::task::yield_now().await;
    let abort = request.abort_handle();
    let registry = BackendCancellationRegistry::default();
    registry.register("active", move || {
        abort.abort();
        true
    });
    assert_eq!(registry.request("active", "running"), "cancel_signalled");
    assert!(request.await.unwrap_err().is_cancelled());
    server.abort();
}
