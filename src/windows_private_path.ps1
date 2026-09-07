# SPDX-License-Identifier: Apache-2.0
# Same ACL rules as the maintained TypeScript trust-store boundary.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
  $path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATH_BASE64__'))
  $operation = '__OPERATION__'
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
  $isDirectory = $operation.StartsWith('directory-')
  # Reject aliases before creation as well as before validation.
  $cursor = $path
  while ($cursor) {
    if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
      if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_PATH' }
    }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ($parent -eq $cursor) { break }
    $cursor = $parent
  }
  if ($operation.EndsWith('-create')) {
    $security = if ($isDirectory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner($sid)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($isDirectory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($principal in @($sid, $system)) {
      $rule = [Security.AccessControl.FileSystemAccessRule]::new($principal, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
      $security.AddAccessRule($rule)
    }
    if ($isDirectory) {
      # The descriptor is applied at creation; existing directories are not repaired.
      [IO.Directory]::CreateDirectory($path, $security) | Out-Null
    } else {
      $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
      $stream.Dispose()
    }
  }
  $attributes = [IO.File]::GetAttributes($path)
  if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_PATH' }
  if ((($attributes -band [IO.FileAttributes]::Directory) -ne 0) -ne $isDirectory) { throw 'PATH_KIND' }
  $acl = if ($isDirectory) { [IO.Directory]::GetAccessControl($path) } else { [IO.File]::GetAccessControl($path) }
  if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'OWNER_DIFFERS' }
  $ownerFull = $false
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'DENY_RULE' }
    if ($rule.IdentityReference.Value -notin @($sid.Value, $system.Value)) { throw 'BROAD_ACCESS' }
    if ($rule.IdentityReference.Value -eq $sid.Value -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) { $ownerFull = $true }
  }
  if (-not $ownerFull) { throw 'OWNER_ACCESS_MISSING' }
  [Console]::Out.Write('OK')
} catch {
  $exception = $_.Exception
  while ($exception.InnerException) { $exception = $exception.InnerException }
  $errorCode = $exception.HResult -band 0xffff
  if ($operation -eq 'file-create' -and $errorCode -in @(80, 183)) { [Console]::Out.Write('EXISTS'); exit 0 }
  [Console]::Out.Write('REFUSED'); exit 1
}
