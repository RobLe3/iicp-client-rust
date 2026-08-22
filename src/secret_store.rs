// SPDX-License-Identifier: Apache-2.0
//! Resolution boundary for portable runtime secret references.
//!
//! Configuration contains only [`SecretRef`](crate::runtime_config::SecretRef)
//! values. Resolution is explicit and returns a redacted, zeroized value. The
//! runtime must resolve required references before it starts network services.

use crate::runtime_config::SecretRef;
use std::fmt;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

pub const SECRET_UNAVAILABLE: &str = "secret_reference_unavailable";
pub const SECRET_PROVIDER_UNSUPPORTED: &str = "secret_provider_unsupported";
pub const SECRET_FILE_UNSAFE: &str = "secret_file_unsafe";
pub const SECRET_MUTATION_UNSUPPORTED: &str = "secret_mutation_unsupported";

/// A resolved secret whose debug/display representations never reveal it and
/// whose allocation is cleared when dropped.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    fn new(mut value: String) -> Result<Self, &'static str> {
        if value.ends_with('\n') {
            value.truncate(value.trim_end_matches(['\r', '\n']).len());
        }
        if value.is_empty() {
            value.zeroize();
            return Err(SECRET_UNAVAILABLE);
        }
        Ok(Self(Zeroizing::new(value)))
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Application-owned external secret providers implement this interface.
/// The reference locator is not the secret itself.
pub trait ExternalSecretProvider {
    fn resolve(&self, provider: &str, reference: &str) -> Result<String, &'static str>;

    fn store(&self, _provider: &str, _reference: &str, _value: &str) -> Result<(), &'static str> {
        Err(SECRET_MUTATION_UNSUPPORTED)
    }

    fn delete(&self, _provider: &str, _reference: &str) -> Result<(), &'static str> {
        Err(SECRET_MUTATION_UNSUPPORTED)
    }
}

pub fn resolve(
    reference: &SecretRef,
    external: Option<&dyn ExternalSecretProvider>,
) -> Result<SecretValue, &'static str> {
    let value = match reference {
        SecretRef::Environment { name } => std::env::var(name).map_err(|_| SECRET_UNAVAILABLE)?,
        SecretRef::File { path } => read_protected_file(Path::new(path))?,
        SecretRef::MacosKeychain { service, account } => resolve_macos_keychain(service, account)?,
        SecretRef::WindowsCredential { target } => resolve_windows_credential(target)?,
        SecretRef::LinuxSecretService { collection, label } => {
            resolve_linux_secret_service(collection, label)?
        }
        SecretRef::External {
            provider,
            reference,
        } => external
            .ok_or(SECRET_PROVIDER_UNSUPPORTED)?
            .resolve(provider, reference)?,
    };
    SecretValue::new(value)
}

/// Store or rotate a secret through the provider selected by the portable
/// reference. Environment references are deliberately read-only: mutating a
/// parent process environment is neither reliable nor a durable secret store.
pub fn store(
    reference: &SecretRef,
    value: &str,
    external: Option<&dyn ExternalSecretProvider>,
) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err(SECRET_UNAVAILABLE);
    }
    match reference {
        SecretRef::File { path } => write_protected_file(Path::new(path), value.as_bytes()),
        SecretRef::External {
            provider,
            reference,
        } => external
            .ok_or(SECRET_PROVIDER_UNSUPPORTED)?
            .store(provider, reference, value),
        _ => Err(SECRET_MUTATION_UNSUPPORTED),
    }
}

/// Remove a secret owned by the selected provider. Missing files are treated
/// as already deleted, while unsafe paths fail closed.
pub fn delete(
    reference: &SecretRef,
    external: Option<&dyn ExternalSecretProvider>,
) -> Result<(), &'static str> {
    match reference {
        SecretRef::File { path } => delete_protected_file(Path::new(path)),
        SecretRef::External {
            provider,
            reference,
        } => external
            .ok_or(SECRET_PROVIDER_UNSUPPORTED)?
            .delete(provider, reference),
        _ => Err(SECRET_MUTATION_UNSUPPORTED),
    }
}

fn read_protected_file(path: &Path) -> Result<String, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| SECRET_UNAVAILABLE)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SECRET_FILE_UNSAFE);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(SECRET_FILE_UNSAFE);
        }
    }
    std::fs::read_to_string(path).map_err(|_| SECRET_UNAVAILABLE)
}

#[cfg(unix)]
fn write_protected_file(path: &Path, value: &[u8]) -> Result<(), &'static str> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let parent = path.parent().ok_or(SECRET_FILE_UNSAFE)?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| SECRET_FILE_UNSAFE)?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(SECRET_FILE_UNSAFE);
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(SECRET_FILE_UNSAFE);
        }
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SECRET_FILE_UNSAFE)?;
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| SECRET_FILE_UNSAFE)?;
        file.write_all(value).map_err(|_| SECRET_UNAVAILABLE)?;
        file.sync_all().map_err(|_| SECRET_UNAVAILABLE)?;
        drop(file);
        std::fs::rename(&temporary, path).map_err(|_| SECRET_UNAVAILABLE)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| SECRET_FILE_UNSAFE)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| SECRET_UNAVAILABLE)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(unix))]
fn write_protected_file(_path: &Path, _value: &[u8]) -> Result<(), &'static str> {
    Err(SECRET_MUTATION_UNSUPPORTED)
}

fn delete_protected_file(path: &Path) -> Result<(), &'static str> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SECRET_UNAVAILABLE),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SECRET_FILE_UNSAFE);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(SECRET_FILE_UNSAFE);
        }
    }
    std::fs::remove_file(path).map_err(|_| SECRET_UNAVAILABLE)
}

#[cfg(target_os = "macos")]
fn resolve_macos_keychain(service: &str, account: &str) -> Result<String, &'static str> {
    let output = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-w", "-s", service, "-a", account])
        .output()
        .map_err(|_| SECRET_UNAVAILABLE)?;
    command_value(output)
}

#[cfg(not(target_os = "macos"))]
fn resolve_macos_keychain(_service: &str, _account: &str) -> Result<String, &'static str> {
    Err(SECRET_PROVIDER_UNSUPPORTED)
}

#[cfg(target_os = "linux")]
fn resolve_linux_secret_service(collection: &str, label: &str) -> Result<String, &'static str> {
    let output = Command::new("secret-tool")
        .args(["lookup", "collection", collection, "label", label])
        .output()
        .map_err(|_| SECRET_UNAVAILABLE)?;
    command_value(output)
}

#[cfg(not(target_os = "linux"))]
fn resolve_linux_secret_service(_collection: &str, _label: &str) -> Result<String, &'static str> {
    Err(SECRET_PROVIDER_UNSUPPORTED)
}

#[cfg(target_os = "windows")]
fn resolve_windows_credential(target: &str) -> Result<String, &'static str> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    let mut wide_target: Vec<u16> = target.encode_utf16().collect();
    wide_target.push(0);
    let mut credential: *mut CREDENTIALW = null_mut();
    // SAFETY: the target is NUL terminated, `credential` is an out pointer,
    // and a successful result is released exactly once with CredFree.
    let found = unsafe { CredReadW(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
    if found == 0 || credential.is_null() {
        return Err(SECRET_UNAVAILABLE);
    }
    // SAFETY: CredentialBlob and its byte count belong to the live credential
    // allocation. Copy before releasing the allocation.
    let bytes = unsafe {
        let record = &*credential;
        std::slice::from_raw_parts(record.CredentialBlob, record.CredentialBlobSize as usize)
            .to_vec()
    };
    // SAFETY: `credential` was allocated by CredReadW and is no longer used.
    unsafe { CredFree(credential.cast()) };
    decode_windows_credential_blob(bytes)
}

#[cfg(not(target_os = "windows"))]
fn resolve_windows_credential(_target: &str) -> Result<String, &'static str> {
    Err(SECRET_PROVIDER_UNSUPPORTED)
}

#[cfg(any(target_os = "windows", test))]
fn decode_windows_credential_blob(bytes: Vec<u8>) -> Result<String, &'static str> {
    if bytes.contains(&0) {
        if bytes.len() % 2 != 0 {
            return Err(SECRET_UNAVAILABLE);
        }
        let words = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|word| *word != 0)
            .collect::<Vec<_>>();
        return String::from_utf16(&words).map_err(|_| SECRET_UNAVAILABLE);
    }
    String::from_utf8(bytes).map_err(|_| SECRET_UNAVAILABLE)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_value(output: std::process::Output) -> Result<String, &'static str> {
    if !output.status.success() {
        return Err(SECRET_UNAVAILABLE);
    }
    String::from_utf8(output.stdout).map_err(|_| SECRET_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct FixtureProvider;
    impl ExternalSecretProvider for FixtureProvider {
        fn resolve(&self, provider: &str, reference: &str) -> Result<String, &'static str> {
            if provider == "fixture" && reference == "node-token" {
                Ok("external-secret".into())
            } else {
                Err(SECRET_UNAVAILABLE)
            }
        }
    }

    struct MutableFixtureProvider(Mutex<Option<String>>);
    impl ExternalSecretProvider for MutableFixtureProvider {
        fn resolve(&self, provider: &str, reference: &str) -> Result<String, &'static str> {
            if provider != "fixture" || reference != "node-token" {
                return Err(SECRET_UNAVAILABLE);
            }
            self.0.lock().unwrap().clone().ok_or(SECRET_UNAVAILABLE)
        }

        fn store(&self, provider: &str, reference: &str, value: &str) -> Result<(), &'static str> {
            if provider != "fixture" || reference != "node-token" {
                return Err(SECRET_UNAVAILABLE);
            }
            *self.0.lock().unwrap() = Some(value.to_owned());
            Ok(())
        }

        fn delete(&self, provider: &str, reference: &str) -> Result<(), &'static str> {
            if provider != "fixture" || reference != "node-token" {
                return Err(SECRET_UNAVAILABLE);
            }
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    #[test]
    fn environment_resolution_is_redacted() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("IICP_TEST_SECRET_REF", "sensitive-value");
        let value = resolve(
            &SecretRef::Environment {
                name: "IICP_TEST_SECRET_REF".into(),
            },
            None,
        )
        .unwrap();
        std::env::remove_var("IICP_TEST_SECRET_REF");
        assert_eq!(value.expose(), "sensitive-value");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
        assert_eq!(value.to_string(), "[REDACTED]");
    }

    #[test]
    fn environment_rotation_and_deletion_are_observed_without_a_secret_cache() {
        let _guard = ENV_LOCK.lock().unwrap();
        let reference = SecretRef::Environment {
            name: "IICP_TEST_ROTATING_SECRET_REF".into(),
        };
        std::env::set_var("IICP_TEST_ROTATING_SECRET_REF", "first");
        assert_eq!(resolve(&reference, None).unwrap().expose(), "first");
        std::env::set_var("IICP_TEST_ROTATING_SECRET_REF", "second");
        assert_eq!(resolve(&reference, None).unwrap().expose(), "second");
        std::env::remove_var("IICP_TEST_ROTATING_SECRET_REF");
        assert_eq!(resolve(&reference, None).unwrap_err(), SECRET_UNAVAILABLE);
    }

    #[test]
    fn external_provider_is_explicit() {
        let reference = SecretRef::External {
            provider: "fixture".into(),
            reference: "node-token".into(),
        };
        assert_eq!(
            resolve(&reference, None).unwrap_err(),
            SECRET_PROVIDER_UNSUPPORTED
        );
        assert_eq!(
            resolve(&reference, Some(&FixtureProvider))
                .unwrap()
                .expose(),
            "external-secret"
        );
    }

    #[test]
    fn external_provider_mutation_is_explicit_and_observable() {
        let provider = MutableFixtureProvider(Mutex::new(None));
        let reference = SecretRef::External {
            provider: "fixture".into(),
            reference: "node-token".into(),
        };
        assert_eq!(
            store(&reference, "first", None),
            Err(SECRET_PROVIDER_UNSUPPORTED)
        );
        store(&reference, "first", Some(&provider)).unwrap();
        assert_eq!(
            resolve(&reference, Some(&provider)).unwrap().expose(),
            "first"
        );
        store(&reference, "second", Some(&provider)).unwrap();
        assert_eq!(
            resolve(&reference, Some(&provider)).unwrap().expose(),
            "second"
        );
        delete(&reference, Some(&provider)).unwrap();
        assert_eq!(
            resolve(&reference, Some(&provider)).unwrap_err(),
            SECRET_UNAVAILABLE
        );
    }

    #[test]
    fn windows_credential_blob_accepts_utf8_and_utf16le() {
        assert_eq!(
            decode_windows_credential_blob(b"utf8-secret".to_vec()).unwrap(),
            "utf8-secret"
        );
        let utf16 = "wide-secret"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode_windows_credential_blob(utf16).unwrap(),
            "wide-secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_provider_rejects_group_readable_and_symlink_files() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("iicp-secret-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let secret = root.join("secret");
        std::fs::write(&secret, "file-secret\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let reference = SecretRef::File {
            path: secret.to_string_lossy().into_owned(),
        };
        assert_eq!(resolve(&reference, None).unwrap().expose(), "file-secret");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(resolve(&reference, None).unwrap_err(), SECRET_FILE_UNSAFE);
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert_eq!(
            resolve(
                &SecretRef::File {
                    path: link.to_string_lossy().into_owned()
                },
                None
            )
            .unwrap_err(),
            SECRET_FILE_UNSAFE
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_provider_store_rotate_and_delete_are_atomic_and_owner_only() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = std::env::temp_dir().join(format!(
            "iicp-secret-lifecycle-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("node-token");
        let reference = SecretRef::File {
            path: path.to_string_lossy().into_owned(),
        };

        store(&reference, "first", None).unwrap();
        assert_eq!(resolve(&reference, None).unwrap().expose(), "first");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        store(&reference, "second", None).unwrap();
        assert_eq!(resolve(&reference, None).unwrap().expose(), "second");
        assert!(std::fs::read_dir(&root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));

        delete(&reference, None).unwrap();
        assert_eq!(resolve(&reference, None).unwrap_err(), SECRET_UNAVAILABLE);
        delete(&reference, None).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
