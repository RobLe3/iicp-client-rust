// SPDX-License-Identifier: Apache-2.0
//! Windows trust-store ACL checks. PowerShell is a bounded platform adapter,
//! not a policy engine; paths are encoded and no caller text is executed.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Windows private-path verification failed",
    )
}

pub(crate) fn verify(path: &Path, operation: &str) -> io::Result<()> {
    let path = path.to_str().ok_or_else(refused)?;
    if !Path::new(path).is_absolute()
        || path.contains('\0')
        || !matches!(
            operation,
            "directory-create" | "directory-check" | "file-create" | "file-check"
        )
    {
        return Err(refused());
    }
    let root = std::env::var_os("SystemRoot").ok_or_else(refused)?;
    if !Path::new(&root).is_absolute() {
        return Err(refused());
    }
    let command = include_str!("windows_private_path.ps1")
        .replace("__PATH_BASE64__", &STANDARD.encode(path.as_bytes()))
        .replace("__OPERATION__", operation);
    run_check(
        &command,
        &Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe"),
        Duration::from_secs(10),
    )
}

fn run_check(command: &str, tool: &Path, timeout: Duration) -> io::Result<()> {
    let encoded: Vec<u8> = command.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut child = Command::new(tool)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &STANDARD.encode(encoded),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| refused())?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(refused());
                }
                let mut result = String::new();
                child
                    .stdout
                    .take()
                    .ok_or_else(refused)?
                    .take(16385)
                    .read_to_string(&mut result)?;
                return match result.trim() {
                    "OK" => Ok(()),
                    "EXISTS" => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
                    _ => Err(refused()),
                };
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(refused());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unencoded_inputs_and_unknown_operations() {
        assert!(verify(Path::new("relative"), "file-check").is_err());
        assert!(verify(Path::new("C:\\bad\0path"), "file-check").is_err());
        assert!(verify(Path::new("C:\\state"), "bad'").is_err());
    }
    #[test]
    fn unavailable_tool_and_timeout_fail_closed() {
        assert!(run_check(
            "[Console]::Out.Write('OK')",
            Path::new("C:\\missing-iicp-security-tool.exe"),
            Duration::from_millis(50)
        )
        .is_err());
        let tool = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let started = Instant::now();
        assert!(run_check("Start-Sleep -Seconds 30", &tool, Duration::from_millis(50)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
