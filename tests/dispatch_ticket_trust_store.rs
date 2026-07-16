use iicp_client::dispatch_ticket_trust::{
    canonical_dispatch_trust_bundle, AdminRecoveryAuthorization, DispatchTrustBundle,
    FileDispatchTrustBundleStore, TrustBundleInstallStatus, TrustBundleStore,
    TrustBundleStoreError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../parity/dispatch-ticket-trust-store-v1.json"
    ))
    .unwrap()
}

fn bundle(name: &str) -> DispatchTrustBundle {
    serde_json::from_value(fixture()["bundles"][name].clone()).unwrap()
}

fn temporary_store(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("iicp-trust-{name}-{}", uuid::Uuid::new_v4()));
    let path = root.join("trust").join("bundle.state");
    (root, path)
}

#[test]
fn canonical_bundle_digests_match_shared_fixture() {
    let data = fixture();
    for (name, expected) in data["canonical_digests"].as_object().unwrap() {
        let canonical = canonical_dispatch_trust_bundle(&bundle(name)).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(canonical));
        assert_eq!(&digest, expected.as_str().unwrap());
    }
}

#[test]
fn shared_store_sequence_and_explicit_recovery() {
    let (root, path) = temporary_store("sequence");
    let store = FileDispatchTrustBundleStore::new(&path);
    let initial = store.install(&bundle("v1"), None).unwrap();
    assert_eq!(initial.status, TrustBundleInstallStatus::Installed);
    assert_eq!(initial.state.unwrap().high_water, 1);
    assert_eq!(
        FileDispatchTrustBundleStore::new(&path)
            .load()
            .unwrap()
            .unwrap()
            .bundle
            .bundle_version,
        1
    );
    assert_eq!(
        store.install(&bundle("v1"), None).unwrap().status,
        TrustBundleInstallStatus::Unchanged
    );
    assert_eq!(
        store.install(&bundle("v1_conflict"), None).unwrap().status,
        TrustBundleInstallStatus::Conflict
    );
    assert_eq!(
        store.install(&bundle("v2"), Some(1)).unwrap().status,
        TrustBundleInstallStatus::Installed
    );
    assert_eq!(
        store.install(&bundle("v1"), None).unwrap().status,
        TrustBundleInstallStatus::Stale
    );
    assert_eq!(
        store.install(&bundle("v2"), Some(1)).unwrap().status,
        TrustBundleInstallStatus::Conflict
    );
    assert_eq!(
        store.recover(&bundle("v1"), None).unwrap().status,
        TrustBundleInstallStatus::RecoveryRequired
    );
    let recovered = store
        .recover(
            &bundle("v1"),
            Some(&AdminRecoveryAuthorization {
                reason: "operator-approved-test-recovery".into(),
                minimum_high_water: 2,
            }),
        )
        .unwrap();
    assert_eq!(recovered.status, TrustBundleInstallStatus::Recovered);
    let state = recovered.state.unwrap();
    assert_eq!((state.bundle.bundle_version, state.high_water), (1, 2));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn corruption_orphan_temp_permissions_and_lock_fail_closed() {
    let (root, path) = temporary_store("failure");
    let store = FileDispatchTrustBundleStore::with_lock_timeout(&path, Duration::ZERO);
    store.install(&bundle("v1"), None).unwrap();
    fs::write(
        path.with_file_name("bundle.state.tmp-interrupted"),
        b"partial",
    )
    .unwrap();
    assert!(store.load().unwrap().is_some());
    fs::write(&path, b"{not-json").unwrap();
    assert!(matches!(
        store.load(),
        Err(TrustBundleStoreError::Corrupt(_))
    ));
    assert_eq!(
        store
            .recover(
                &bundle("v1"),
                Some(&AdminRecoveryAuthorization {
                    reason: "repair-test".into(),
                    minimum_high_water: 1,
                }),
            )
            .unwrap()
            .status,
        TrustBundleInstallStatus::Recovered
    );
    fs::write(store.lock_path(), b"held").unwrap();
    assert!(matches!(
        store.install(&bundle("v2"), None),
        Err(TrustBundleStoreError::Locked)
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_writers_finish_at_highest_version() {
    let (root, path) = temporary_store("concurrent");
    let store = Arc::new(FileDispatchTrustBundleStore::new(&path));
    store.install(&bundle("v1"), None).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for candidate in [
        bundle("v2"),
        serde_json::from_value(serde_json::json!({
            "bundle_version": 3,
            "issuer": "did:web:directory.example",
            "keys": []
        }))
        .unwrap(),
    ] {
        let worker_store = Arc::clone(&store);
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            worker_store.install(&candidate, None).unwrap().status
        }));
    }
    barrier.wait();
    for handle in handles {
        assert!(matches!(
            handle.join().unwrap(),
            TrustBundleInstallStatus::Installed | TrustBundleInstallStatus::Stale
        ));
    }
    let state = store.load().unwrap().unwrap();
    assert_eq!((state.bundle.bundle_version, state.high_water), (3, 3));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn symbolic_link_store_fails_closed() {
    use std::os::unix::fs::symlink;

    let (root, path) = temporary_store("symlink");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = root.join("target");
    fs::write(&target, b"{}").unwrap();
    symlink(&target, &path).unwrap();
    assert!(matches!(
        FileDispatchTrustBundleStore::new(&path).load(),
        Err(TrustBundleStoreError::Corrupt(_))
    ));
    fs::remove_dir_all(root).unwrap();
}
