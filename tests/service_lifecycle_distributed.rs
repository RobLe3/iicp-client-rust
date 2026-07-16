use iicp_client::service_lifecycle_distributed::evaluate_distributed_lifecycle;
use serde_json::Value;

#[test]
fn distributed_lifecycle_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/service-lifecycle-distributed-v1.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        assert_eq!(
            evaluate_distributed_lifecycle(vector),
            vector["expected"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}
