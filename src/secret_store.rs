// SPDX-License-Identifier: Apache-2.0
//! Resolution boundary for portable runtime secret references.
//!
//! Configuration contains only [`SecretRef`](crate::runtime_config::SecretRef)
//! values. Resolution is explicit and returns a redacted, zeroized value. The
//! runtime must resolve required references before it starts network services.

use crate::runtime_config::SecretRef;
use std::fmt;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

pub const SECRET_UNAVAILABLE: &str = "secret_reference_unavailable";
pub const SECRET_PROVIDER_UNSUPPORTED: &str = "secret_provider_unsupported";
pub const SECRET_FILE_UNSAFE: &str = "secret_file_unsafe";

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
}
