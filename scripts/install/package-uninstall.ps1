#!/usr/bin/env pwsh
# Immutable, manifest-verified ASG Windows tail. Never executes user-data scripts.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Prefix,
    [Parameter(Mandatory = $true)][string]$Catalog,
    [Parameter(Mandatory = $true)][string]$Nonce,
    [Parameter(Mandatory = $true)][UInt64]$DeadlineTick,
    [Parameter(Mandatory = $true)][UInt64]$ReceiptSequence,
    [Parameter(Mandatory = $true)][string]$ReceiptSha256,
    [Parameter(Mandatory = $true)][string]$SealSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$handles = [Collections.Generic.List[IDisposable]]::new()
$complete = $false
$tailRemoved = $false
$runnerRemoved = $false
$reason = 'identity_changed'
$verified = $false
$helperRoot = $null

# Ordinary-file handles deny writes/replacement throughout hashing and deletion.
# OS lock acquisition, not a PID or elapsed delay, proves that the owner exited.
$native = @"
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
namespace AsgUninstallV1 {
    public sealed class Pin : IDisposable {
        public SafeFileHandle Handle;
        public UInt64 Volume, Index, Size;
        public void Dispose() { if (Handle != null) { Handle.Dispose(); Handle = null; } }
    }
    public static class Native {
        const UInt32 Read = 0x80000000, Write = 0x40000000, Delete = 0x00010000;
        [StructLayout(LayoutKind.Sequential)] struct Info {
            public UInt32 Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, WriteTime;
            public UInt32 Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)] struct Overlapped {
            public UIntPtr Internal, InternalHigh;
            public UInt32 Offset, OffsetHigh;
            public IntPtr Event;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFileW(string p, UInt32 access, UInt32 share, IntPtr security, UInt32 creation, UInt32 flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h, out Info i);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern UInt32 GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder p, UInt32 n, UInt32 flags);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool LockFileEx(SafeFileHandle h, UInt32 flags, UInt32 reserved, UInt32 low, UInt32 high, ref Overlapped o);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h, UInt32 kind, ref byte value, UInt32 size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle h);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle source, IntPtr targetProcess, out SafeFileHandle target, UInt32 access, bool inherit, UInt32 options);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] public static extern UInt64 GetTickCount64();
        static void Fail() { throw new IOException("verified owned cleanup is pending"); }
        public static void Deadline(UInt64 tick) {
            UInt64 now = GetTickCount64();
            if (tick <= now || tick - now > 30000) Fail();
        }
        public static string Full(string path) {
            if (String.IsNullOrEmpty(path) || !Path.IsPathRooted(path)) Fail();
            string p = path;
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p.Substring(8);
            else if (p.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) p = p.Substring(4);
            if (p.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase)) Fail();
            foreach (string s in p.Replace('/', '\\').Split('\\'))
                if (s == "." || s == ".." || s.EndsWith(" ") || s.EndsWith(".")) Fail();
            string full = Path.GetFullPath(p);
            for (string parent = full; !String.IsNullOrEmpty(parent); parent = Path.GetDirectoryName(parent))
                if (((UInt32)File.GetAttributes(parent) & 0x400) != 0) Fail();
            return full;
        }
        public static string Child(string root, string relative) {
            if (String.IsNullOrEmpty(relative) || relative.Length > 240 || relative.Contains(":") || relative.Contains("\\") || relative.StartsWith("/")) Fail();
            foreach (string s in relative.Split('/')) {
                if (s.Length == 0 || s == "." || s == "..") Fail();
                foreach (char c in s) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || "._+-".IndexOf(c) >= 0)) Fail();
            }
            string b = Full(root).TrimEnd('\\');
            string p = Path.GetFullPath(Path.Combine(b, relative.Replace('/', '\\')));
            if (!p.StartsWith(b + "\\", StringComparison.OrdinalIgnoreCase)) Fail();
            return p;
        }
        static Pin Open(string path, UInt32 access, UInt32 share, bool directory, bool create) {
            string full = create ? Child(Path.GetDirectoryName(path), Path.GetFileName(path)) : Full(path);
            var h = CreateFileW(full, access, share, IntPtr.Zero, create ? 1U : 3U, 0x00200000U | (directory ? 0x02000000U : 0U), IntPtr.Zero);
            if (h.IsInvalid) { int code = Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(code); }
            Info i;
            if (!GetFileInformationByHandle(h, out i) || (i.Attributes & 0x400) != 0 || ((i.Attributes & 0x10) != 0) != directory || (!directory && i.Links != 1)) { h.Dispose(); Fail(); }
            var b = new StringBuilder(32768);
            UInt32 n = GetFinalPathNameByHandleW(h, b, (UInt32)b.Capacity, 0);
            if (n == 0 || n >= (UInt32)b.Capacity || !String.Equals(Full(b.ToString()), full, StringComparison.OrdinalIgnoreCase)) { h.Dispose(); Fail(); }
            return new Pin { Handle = h, Volume = i.Volume, Index = ((UInt64)i.IndexHigh << 32) | i.IndexLow, Size = ((UInt64)i.SizeHigh << 32) | i.SizeLow };
        }
        static FileStream Stream(Pin p, FileAccess access) {
            SafeFileHandle duplicate;
            if (!DuplicateHandle(GetCurrentProcess(), p.Handle, GetCurrentProcess(), out duplicate, 0, false, 2)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new FileStream(duplicate, access, 65536, false);
        }
        static void Match(Pin p, UInt64 size, UInt64 volume, UInt64 index) {
            if (p.Size != size || p.Volume != volume || p.Index != index) Fail();
        }
        static string Digest(Pin p, UInt64 tick) {
            using (var sha = SHA256.Create()) using (var stream = Stream(p, FileAccess.Read)) {
                byte[] buffer = new byte[65536];
                UInt64 size = 0;
                int n;
                while ((n = stream.Read(buffer, 0, buffer.Length)) != 0) {
                    Deadline(tick);
                    size += (UInt64)n;
                    if (size > 17179869184UL) Fail();
                    sha.TransformBlock(buffer, 0, n, buffer, 0);
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                if (size != p.Size) Fail();
                return BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
            }
        }
        public static Pin Directory(string path, UInt64 volume, UInt64 index) {
            Pin p = Open(path, Read, 3, true, false);
            if (p.Volume != volume || p.Index != index) { p.Dispose(); Fail(); }
            return p;
        }
        public static byte[] Snapshot(string path, UInt64 size, UInt64 volume, UInt64 index, string sha, UInt64 tick) {
            Deadline(tick);
            using (Pin p = Open(path, Read, 1, false, false)) {
                Match(p, size, volume, index);
                return Bytes(p, sha, tick);
            }
        }
        static byte[] Bytes(Pin p, string sha, UInt64 tick) {
            if (p.Size > 4194304) Fail();
            using (var stream = Stream(p, FileAccess.Read)) using (var bytes = new MemoryStream()) {
                byte[] buffer = new byte[65536]; int n;
                while ((n = stream.Read(buffer, 0, buffer.Length)) != 0) { Deadline(tick); bytes.Write(buffer, 0, n); if (bytes.Length > 4194304) Fail(); }
                byte[] result = bytes.ToArray();
                if ((UInt64)result.Length != p.Size) Fail();
                using (var hash = SHA256.Create()) if (BitConverter.ToString(hash.ComputeHash(result)).Replace("-", "").ToLowerInvariant() != sha) Fail();
                return result;
            }
        }
        public static byte[] BoundSnapshot(string path, string sha, UInt64 tick) {
            Deadline(tick);
            using (Pin p = Open(path, Read, 1, false, false)) return Bytes(p, sha, tick);
        }
        public static void Verify(string path, UInt64 size, UInt64 volume, UInt64 index, string sha, UInt64 tick) {
            Deadline(tick);
            using (Pin p = Open(path, Read, 1, false, false)) { Match(p, size, volume, index); if (Digest(p, tick) != sha) Fail(); }
        }
        public static Pin ExitLock(string path, UInt64 volume, UInt64 index, UInt64 tick) {
            while (true) {
                Deadline(tick);
                Pin p = Open(path, Read | Write, 3, false, false);
                if (p.Size != 0 || p.Volume != volume || p.Index != index) { p.Dispose(); Fail(); }
                Overlapped o = new Overlapped();
                if (LockFileEx(p.Handle, 3, 0, 1, 0, ref o)) return p;
                int code = Marshal.GetLastWin32Error(); p.Dispose();
                if (code != 33 && code != 32) throw new Win32Exception(code);
                System.Threading.Thread.Sleep(5);
            }
        }
        public static bool Remove(string path, UInt64 size, UInt64 volume, UInt64 index, string sha, UInt64 tick) {
            while (true) {
                Deadline(tick);
                try {
                    using (Pin p = Open(path, Read | Delete, 1, false, false)) {
                        Match(p, size, volume, index);
                        if (Digest(p, tick) != sha) Fail();
                        byte disposition = 1;
                        if (!SetFileInformationByHandle(p.Handle, 4, ref disposition, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    return !File.Exists(path);
                } catch (FileNotFoundException) { return true; }
                  catch (Win32Exception e) {
                    if (e.NativeErrorCode != 5 && e.NativeErrorCode != 32 && e.NativeErrorCode != 33) throw;
                    System.Threading.Thread.Sleep(5);
                }
            }
        }
        public static void WriteNew(string path, byte[] bytes, UInt64 tick) {
            Deadline(tick);
            using (Pin p = Open(path, Write, 1, false, true)) {
                using (var stream = Stream(p, FileAccess.Write)) { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
                if (!FlushFileBuffers(p.Handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
"@
function Read-Proof([string]$Root, $Proof) {
    if ($null -eq $Proof -or $Proof.digest -notmatch '^[0-9a-f]{64}$' -or @($Proof.identity).Count -ne 2) { throw 'identity_changed' }
    return ,([AsgUninstallV1.Native]::Snapshot([AsgUninstallV1.Native]::Child($Root, [string]$Proof.relative), [UInt64]$Proof.size, [UInt64]$Proof.identity[0], [UInt64]$Proof.identity[1], [string]$Proof.digest, $DeadlineTick))
}
function Verify-Proof([string]$Root, $Proof) {
    [AsgUninstallV1.Native]::Verify([AsgUninstallV1.Native]::Child($Root, [string]$Proof.relative), [UInt64]$Proof.size, [UInt64]$Proof.identity[0], [UInt64]$Proof.identity[1], [string]$Proof.digest, $DeadlineTick)
}
function Remove-Proof([string]$Root, $Proof) {
    return [AsgUninstallV1.Native]::Remove([AsgUninstallV1.Native]::Child($Root, [string]$Proof.relative), [UInt64]$Proof.size, [UInt64]$Proof.identity[0], [UInt64]$Proof.identity[1], [string]$Proof.digest, $DeadlineTick)
}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $Nonce -notmatch '^[A-Za-z0-9_-]{1,128}$' -or $ReceiptSequence -lt 1 -or $ReceiptSequence -gt 256 -or $ReceiptSha256 -notmatch '^[0-9a-f]{64}$' -or $SealSha256 -notmatch '^[0-9a-f]{64}$') { throw 'identity_changed' }
    Add-Type -TypeDefinition $native -ErrorAction Stop
    [AsgUninstallV1.Native]::Deadline($DeadlineTick)
    $Prefix = [AsgUninstallV1.Native]::Full($Prefix)
    $Catalog = [IO.Path]::GetFullPath($Catalog)
    $dataRoot = [AsgUninstallV1.Native]::Full([IO.Path]::GetDirectoryName($Catalog))
    $journalRoot = [AsgUninstallV1.Native]::Child($Prefix, 'uninstall')
    $helperRoot = [AsgUninstallV1.Native]::Child($journalRoot, 'helper')
    $sealBytes = [AsgUninstallV1.Native]::BoundSnapshot([AsgUninstallV1.Native]::Child($helperRoot, 'seal.json'), $SealSha256, $DeadlineTick)
    $seal = [Text.Encoding]::UTF8.GetString($sealBytes) | ConvertFrom-Json
    if ($seal.schema -cne 'asg.uninstall-seal/v1' -or $seal.owner.nonce -cne $Nonce -or $seal.owner.catalog_name -cne [IO.Path]::GetFileName($Catalog)) { throw 'identity_changed' }
    foreach ($pair in @(@($Prefix, $seal.roots.prefix), @($dataRoot, $seal.roots.data), @($journalRoot, $seal.roots.journal), @($helperRoot, $seal.roots.helper))) {
        if (@($pair[1]).Count -ne 2) { throw 'identity_changed' }
        $handles.Add([AsgUninstallV1.Native]::Directory([string]$pair[0], [UInt64]$pair[1][0], [UInt64]$pair[1][1]))
    }
    $statePath = [AsgUninstallV1.Native]::Child($journalRoot, ('state-{0:D6}.json' -f $ReceiptSequence))
    $stateBytes = [AsgUninstallV1.Native]::BoundSnapshot($statePath, $ReceiptSha256, $DeadlineTick)
    $state = [Text.Encoding]::UTF8.GetString($stateBytes) | ConvertFrom-Json
    $plan = $state.after_exit
    if ($state.schema -cne 'asg.uninstall-state/v1' -or $state.sequence -ne $ReceiptSequence -or $state.owner.nonce -cne $Nonce -or $state.owner.installation_id -cne $seal.owner.installation_id -or $state.owner.prefix_root -cne $seal.owner.prefix_root -or $state.owner.data_root -cne $seal.owner.data_root -or $state.owner.keep_data -ne $seal.owner.keep_data -or $plan.schema -cne 'asg.uninstall-helper/v1' -or $plan.nonce -cne $Nonce -or $plan.deadline_tick -ne $DeadlineTick -or !$plan.payload_complete -or !$plan.tail_pending -or $plan.seal.digest -cne $SealSha256 -or $state.report.package_cleanup_pending -or $state.report.private_metadata_cleanup_pending) { throw 'identity_changed' }
    $owner = [Text.Encoding]::UTF8.GetString((Read-Proof $journalRoot $seal.owner_file)) | ConvertFrom-Json
    if ($owner.nonce -cne $Nonce -or $owner.installation_id -cne $seal.owner.installation_id -or $owner.data_root -cne $seal.owner.data_root -or $owner.prefix_root -cne $seal.owner.prefix_root -or $owner.keep_data -ne $seal.owner.keep_data) { throw 'identity_changed' }
    if ($plan.runner.relative -cne 'helper/runner.exe' -or $plan.tail.relative -cne 'helper/tail.ps1' -or $plan.parent_exit.relative -cne 'helper/parent-exit.lock' -or $plan.runner_exit.relative -cne 'helper/runner-exit.lock' -or $plan.manifest.relative -cne 'helper/PACKAGE-MANIFEST.tsv' -or $seal.tail_source.relative -cne 'helper/tail-source.ps1') { throw 'identity_changed' }
    if (![string]::Equals([AsgUninstallV1.Native]::Full($PSCommandPath), [AsgUninstallV1.Native]::Child($journalRoot, $plan.tail.relative), [StringComparison]::OrdinalIgnoreCase)) { throw 'identity_changed' }
    $null = Read-Proof $journalRoot $plan.tail
    $null = Read-Proof $journalRoot $seal.tail_source
    $manifest = [Text.Encoding]::ASCII.GetString((Read-Proof $journalRoot $plan.manifest))
    if ($plan.tail.digest -cne $seal.tail_source.digest -or $plan.tail.size -ne $seal.tail_source.size -or $plan.manifest.digest -cne $seal.package_manifest_sha256) { throw 'identity_changed' }
    $directory = $null; $tailMember = $null; $runnerMember = $null
    foreach ($line in $manifest.Split("`n")) {
        $parts = $line.Split("`t")
        if ($parts.Count -eq 2 -and $parts[0] -ceq 'dir') { $directory = $parts[1] }
        if ($parts.Count -eq 5 -and $parts[0] -ceq 'file' -and $parts[4] -cmatch '/helpers/package-uninstall\.ps1$') { $tailMember = $parts }
        if ($parts.Count -eq 5 -and $parts[0] -ceq 'file' -and $parts[4] -cmatch '^versions/[^/]+/agent-session-grep\.exe$') { $runnerMember = $parts }
    }
    if ($null -eq $directory -or $null -eq $tailMember -or $null -eq $runnerMember -or $tailMember[4] -cne "$directory/helpers/package-uninstall.ps1" -or $tailMember[1] -cne $plan.tail.digest -or [UInt64]$tailMember[3] -ne $plan.tail.size -or $runnerMember[1] -cne $plan.runner.digest -or [UInt64]$runnerMember[3] -ne $plan.runner.size) { throw 'identity_changed' }
    foreach ($proof in @($plan.parent_exit, $plan.runner_exit)) {
        if ($proof.size -ne 0 -or $proof.digest -cne 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') { throw 'identity_changed' }
        $handles.Add([AsgUninstallV1.Native]::ExitLock([AsgUninstallV1.Native]::Child($journalRoot, $proof.relative), [UInt64]$proof.identity[0], [UInt64]$proof.identity[1], $DeadlineTick))
    }
    if ($plan.installation_lock.relative -cne 'maintenance-job-696e7374616c6c6174696f6e2d757064617465.lock' -or $plan.installation_lock.size -ne 0 -or $plan.installation_lock.digest -cne $plan.parent_exit.digest) { throw 'identity_changed' }
    $handles.Add([AsgUninstallV1.Native]::ExitLock([AsgUninstallV1.Native]::Child($Prefix, $plan.installation_lock.relative), [UInt64]$plan.installation_lock.identity[0], [UInt64]$plan.installation_lock.identity[1], $DeadlineTick))
    $lockNames = @('policy-owner.lock','policy-emission.lock','control-create.lock','catalog-handles.lock','history-readers.lock','background.lock','supervisor.lock','maintenance-job-6f776e65642d7075726765.lock')
    if (@($plan.data_locks).Count -ne $lockNames.Count) { throw 'identity_changed' }
    foreach ($proof in $plan.data_locks) {
        if ($proof.relative -cnotin $lockNames -or $proof.size -ne 0 -or $proof.digest -cne $plan.parent_exit.digest) { throw 'identity_changed' }
        $handles.Add([AsgUninstallV1.Native]::ExitLock([AsgUninstallV1.Native]::Child($dataRoot, $proof.relative), [UInt64]$proof.identity[0], [UInt64]$proof.identity[1], $DeadlineTick))
    }
    if (!$seal.owner.keep_data) {
        if (!$state.report.corpus_removed -or $state.report.control_cleanup_pending -or !$state.control_retired -or $null -eq $plan.retirement_marker -or $plan.retirement_marker.relative -cne '.asg-control-retired') { throw 'identity_changed' }
        $marker = [Text.Encoding]::UTF8.GetString((Read-Proof $dataRoot $plan.retirement_marker)) | ConvertFrom-Json
        if ($marker.schema -cne 'asg.control-retirement/v1' -or $marker.installation_id -cne $seal.owner.installation_id -or $marker.operation_id -cne $Nonce -or $marker.catalog_incarnation -cne $seal.catalog_incarnation -or $marker.control_root_id -cne $seal.owner.data_root -or $marker.prefix_root_id -cne $seal.owner.prefix_root -or $marker.control_seq -ne $seal.policy.control_seq -or $marker.policy_epoch -ne $seal.policy.policy_epoch) { throw 'identity_changed' }
    } else {
        if (!$state.report.catalog_and_policy_retained -or !$state.report.continuation_cache_cleared -or $null -ne $plan.retirement_marker -or @($plan.retained_data).Count -lt 2) { throw 'identity_changed' }
        foreach ($proof in $plan.retained_data) { Verify-Proof $dataRoot $proof }
    }
    $verified = $true
    # Only these two fixed private files may be removed. Seals, owner locks,
    # receipts and preserved source/settings evidence remain; no parent removal.
    # Script first: on failure to remove the running image, the verified runner
    # can recreate this exact script from its immutable tail-source copy.
    $reason = 'tail_cleanup_pending'
    $tailRemoved = Remove-Proof $journalRoot $plan.tail
    $reason = 'runner_cleanup_pending'
    $runnerRemoved = Remove-Proof $journalRoot $plan.runner
    $complete = $tailRemoved -and $runnerRemoved
} catch {
    # The durable native pending receipt is the recovery authority, not stderr.
} finally {
    if ($verified -and $null -ne $helperRoot) {
        try {
            $result = [ordered]@{
                schema = 'asg.uninstall-tail-result/v1'; nonce = $Nonce;
                seal_sha256 = $SealSha256; receipt_sequence = $ReceiptSequence;
                receipt_sha256 = $ReceiptSha256; deadline_tick = $DeadlineTick;
                tail_removed = $tailRemoved; runner_removed = $runnerRemoved;
                complete = $complete; reason = $(if ($complete) { 'complete' } else { $reason })
            }
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Compress))
            [AsgUninstallV1.Native]::WriteNew([AsgUninstallV1.Native]::Child($helperRoot, ('tail-result-{0:D6}.json' -f $ReceiptSequence)), $bytes, $DeadlineTick)
        } catch { $complete = $false }
    }
    for ($index = $handles.Count - 1; $index -ge 0; $index--) { $handles[$index].Dispose() }
}
if ($complete) { exit 0 }
exit 10
