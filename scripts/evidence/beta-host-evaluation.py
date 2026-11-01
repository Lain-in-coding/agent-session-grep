#!/usr/bin/env python3
"""Private, bounded host capture and transparent installed-ASG stdio proxy.

Python 3.10+, standard library only. No host configuration is written, no
permission flags are added, and no prompt or MCP response is injected. Raw
files belong only in an ignored/external private output root. A summary is
capture evidence, never automatic held-out acceptance. CLI examples:

  python scripts/evidence/beta-host-evaluation.py run --help
  python scripts/evidence/beta-host-evaluation.py proxy --help

Native formats: Claude --print --output-format stream-json --verbose;
Codex exec --json --cd WORKDIR -. Effective permissions stay in the explicitly
supplied isolated profile. Sources: code.claude.com/docs/en/cli-reference and
developers.openai.com/codex/noninteractive.md. Proxy parsing is observational;
JSONL and Content-Length frames are copied without reserialization.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence

SCHEMA = "agent-session-grep.beta-host-evaluation/v1"
CHUNK = 65536
MAX_FRAME = 16 * 1024 * 1024
POLL = 0.025
# Measured clean Codex exit took about 3.45 s after its terminal event.
# Grace applies only after a terminal event; the hard timeout still bounds the run.
DEFAULT_COMPLETION_GRACE_SECONDS = 10.0
REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = {
    "search_sessions": "search", "get_message": "direct-read",
    "get_session_context": "context", "get_session_resume": "direct-read",
    "list_sessions": "search", "generate_handoff": "handoff",
    "list_providers": "other", "session_stats": "other", "get_session_stats": "other", "get_status": "status", "status": "status",
    "doctor": "doctor",
}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
PRIVATE_FORM = re.compile(
    r"(?i)(?<![A-Za-z0-9])[a-z]:[/\\]|\\\\[^\s]+|"
    r"/(?:Users|home|tmp|private|var|etc)/|~[/\\]|"
    r"(?:bearer\s+|(?:api[_-]?key|password|access[_-]?token)\s*[:=])"
)
# codex-cli 0.166.0 reports a configured model missing from its built-in catalog
# (for example a router model) as this non-fatal error item on every turn.
FALLBACK_METADATA_PREFIX = "Model metadata for `"
FALLBACK_METADATA_SUFFIX = ("` not found. Defaulting to fallback metadata; "
                            "this can degrade performance and cause issues.")


class CaptureError(Exception):
    """A stable error code; never embed a path, argv or native error text."""


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha_file(path: Path, length: int | None = None) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        remaining = length
        while remaining is None or remaining > 0:
            chunk = handle.read(CHUNK if remaining is None else min(CHUNK, remaining))
            if not chunk:
                break
            result.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    if length is not None and remaining:
        raise CaptureError("capture_file_changed")
    return result.hexdigest()


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def unavailable(reason: str = "host_not_exposed") -> dict:
    return {"status": "unavailable", "reason_code": reason,
            "detail": "No complete verified measurement is available for this field."}


def measured(value: int | float, unit: str, method: str, complete: bool) -> dict:
    return {"status": "observed", "value": value, "unit": unit, "method": method,
            "coverage": "full-evaluation-episode" if complete else "partial-episode"}


def nonnegative(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def checked_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    for component in [*reversed(absolute.parents), absolute]:
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise CaptureError("linked_directory_refused")
        if not stat.S_ISDIR(info.st_mode):
            raise CaptureError("directory_required")
    return absolute.resolve(strict=True)


def checked_file(path: Path) -> Path:
    parent = checked_directory(path.parent)
    candidate = parent / path.name
    info = candidate.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise CaptureError("regular_file_required")
    return candidate


def create_output(root: Path, run_id: str) -> Path:
    if not RUN_ID.fullmatch(run_id) or run_id in {".", ".."}:
        raise CaptureError("invalid_run_id")
    resolved = checked_directory(root)
    try:
        relative = resolved.relative_to(REPO_ROOT)
    except ValueError:
        relative = None
    if relative is not None and (not relative.parts or not (
        relative.parts[0] in {"evidence-output", "target"} or relative.parts[0].startswith("target-")
    )):
        raise CaptureError("raw_output_must_be_ignored_or_external")
    target = resolved / run_id
    try:
        target.mkdir(mode=0o700)
    except FileExistsError as error:
        raise CaptureError("output_already_exists") from error
    if checked_directory(target).parent != resolved:
        raise CaptureError("output_containment_failed")
    return target


def exclusive_file(output: Path, name: str) -> BinaryIO:
    if Path(name).name != name or name in {".", ".."}:
        raise CaptureError("invalid_output_member")
    checked_directory(output)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(output / name, flags, 0o600)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise CaptureError("output_not_regular")
    return os.fdopen(descriptor, "wb", buffering=0)


def write_json(output: Path, name: str, value: Any) -> None:
    with exclusive_file(output, name) as handle:
        handle.write(json_bytes(value) + b"\n")
        handle.flush()


def bounded_json(path: Path) -> Any:
    path = checked_file(path)
    if path.stat().st_size > MAX_FRAME:
        raise CaptureError("input_json_too_large")
    try:
        return json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as error:
        raise CaptureError("invalid_input_json") from error


def checked_argv(argv: Sequence[str]) -> list[str]:
    if not argv or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in argv):
        raise CaptureError("invalid_command_argv")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise CaptureError("explicit_executable_required")
    checked_file(executable)
    return list(argv)


def host_argv(host: str, command: Sequence[str], workdir: Path, *, settings: Path | None = None,
              mcp_config: Path | None = None, config_profile: str | None = None,
              model: str | None = None, max_turns: int | None = None) -> list[str]:
    argv = checked_argv(command)
    if host == "claude-code":
        argv += ["--print", "--output-format", "stream-json", "--verbose"]
        if settings is not None:
            argv += ["--settings", str(checked_file(settings))]
        if mcp_config is not None:
            argv += ["--mcp-config", str(checked_file(mcp_config)), "--strict-mcp-config"]
        if max_turns is not None:
            if max_turns < 1:
                raise CaptureError("invalid_max_turns")
            argv += ["--max-turns", str(max_turns)]
    elif host == "codex":
        if settings is not None or mcp_config is not None or max_turns is not None:
            raise CaptureError("codex_uses_supplied_profile_config")
        argv += ["exec", "--json", "--cd", str(workdir)]
        if config_profile is not None:
            if not IDENTIFIER.fullmatch(config_profile):
                raise CaptureError("invalid_config_profile")
            argv += ["--profile", config_profile]
    else:
        raise CaptureError("unsupported_host")
    if model is not None:
        if not IDENTIFIER.fullmatch(model):
            raise CaptureError("invalid_model_identifier")
        argv += ["--model", model]
    if host == "codex":
        argv.append("-")
    return argv


def profile_environment(host: str, profile: Path, supplied: Mapping[str, str] | None) -> dict[str, str]:
    # Inherit the parent's already-authorized environment opaquely. Never inspect,
    # enumerate in output, fingerprint, or store credential values/names.
    environment = dict(os.environ if supplied is None else supplied)
    environment["CLAUDE_CONFIG_DIR" if host == "claude-code" else "CODEX_HOME"] = str(profile)
    return environment


class ProcessTree:
    """Contain only this launch, admitting Windows children before resuming."""

    def __init__(self) -> None:
        self.job = None
        self.process: subprocess.Popen | None = None
        self.cleanup = "not_started"
        self.method = "posix-session" if os.name != "nt" else "windows-job-suspended-admission"
        if os.name == "nt":
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            self.kernel = kernel
            kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel.CreateJobObjectW.restype = wintypes.HANDLE
            kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
            kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.WaitForSingleObject.restype = wintypes.DWORD
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]

            class BasicLimit(ctypes.Structure):
                _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                            ("flags", wintypes.DWORD), ("min_working", ctypes.c_size_t),
                            ("max_working", ctypes.c_size_t), ("active_limit", wintypes.DWORD),
                            ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                            ("scheduling", wintypes.DWORD)]

            class IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_uint64) for name in
                            ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

            class ExtendedLimit(ctypes.Structure):
                _fields_ = [("basic", BasicLimit), ("io", IoCounters),
                            ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                            ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]

            self.job = kernel.CreateJobObjectW(None, None)
            limit = ExtendedLimit()
            limit.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self.job or not kernel.SetInformationJobObject(self.job, 9, ctypes.byref(limit), ctypes.sizeof(limit)):
                if self.job:
                    kernel.CloseHandle(self.job)
                    self.job = None
                raise CaptureError("process_tree_containment_unavailable")

    def spawn(self, argv: Sequence[str], **kwargs: Any) -> subprocess.Popen:
        try:
            if os.name == "nt":
                kwargs["creationflags"] = 0x00000004 | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            else:
                kwargs["start_new_session"] = True
            process = subprocess.Popen(argv, **kwargs)
            self.process = process
            if os.name == "nt":
                if not self.kernel.AssignProcessToJobObject(self.job, int(process._handle)):
                    raise CaptureError("process_tree_admission_failed")
                self._resume_primary(process.pid)
            self.cleanup = "running"
            return process
        except BaseException:
            if self.process is not None:
                self.process.kill()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            self.close()
            raise

    def _resume_primary(self, pid: int) -> None:
        from ctypes import wintypes

        class ThreadEntry(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
                        ("thread_id", wintypes.DWORD), ("owner_pid", wintypes.DWORD),
                        ("priority", wintypes.LONG), ("delta", wintypes.LONG), ("flags", wintypes.DWORD)]

        kernel = self.kernel
        kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        kernel.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenThread.restype = wintypes.HANDLE
        kernel.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel.ResumeThread.restype = wintypes.DWORD
        snapshot = kernel.CreateToolhelp32Snapshot(4, 0)
        if snapshot in {None, ctypes.c_void_p(-1).value}:
            raise CaptureError("suspended_launch_thread_unavailable")
        resumed = 0
        try:
            row = ThreadEntry()
            row.size = ctypes.sizeof(row)
            present = kernel.Thread32First(snapshot, ctypes.byref(row))
            while present:
                if row.owner_pid == pid:
                    handle = kernel.OpenThread(2, False, row.thread_id)
                    if handle:
                        try:
                            result = kernel.ResumeThread(handle)
                            if result == 1:
                                resumed += 1
                        finally:
                            kernel.CloseHandle(handle)
                present = kernel.Thread32Next(snapshot, ctypes.byref(row))
        finally:
            kernel.CloseHandle(snapshot)
        if resumed != 1:
            raise CaptureError("suspended_launch_resume_failed")

    def _windows_pids(self, deadline: float) -> list[int] | None:
        from ctypes import wintypes

        capacity = 64
        while capacity <= 65536 and time.monotonic() < deadline:
            class ProcessIds(ctypes.Structure):
                _fields_ = [("assigned", wintypes.DWORD), ("listed", wintypes.DWORD),
                            ("pids", ctypes.c_size_t * capacity)]

            data = ProcessIds()
            ok = self.kernel.QueryInformationJobObject(self.job, 3, ctypes.byref(data), ctypes.sizeof(data), None)
            if ok and data.assigned == data.listed and data.listed <= capacity:
                return list(data.pids[:data.listed])
            if not ok and ctypes.get_last_error() != 234:  # ERROR_MORE_DATA
                return None
            capacity = max(capacity * 2, int(data.assigned))
        return None

    def _stop_windows(self, deadline: float) -> str:
        from ctypes import wintypes

        process = self.process
        assert process is not None
        self.cleanup = "incomplete"
        # NULL queries the caller's job, not this launch's already-closed job.
        if self.job is None:
            return self.cleanup
        held = {process.pid: int(process._handle)}
        owned = []
        try:
            while time.monotonic() < deadline:
                pids = self._windows_pids(deadline)
                if pids is None:
                    break
                for pid in pids:
                    if pid in held:
                        continue
                    if time.monotonic() >= deadline:
                        return self.cleanup
                    handle = self.kernel.OpenProcess(0x00100000 | 0x0001 | 0x1000, False, pid)
                    if not handle:
                        if ctypes.get_last_error() == 87:  # Process already destroyed.
                            continue
                        return self.cleanup
                    owned.append(handle)
                    member = wintypes.BOOL()
                    if not self.kernel.IsProcessInJob(handle, self.job, ctypes.byref(member)) or not member.value:
                        return self.cleanup
                    held[pid] = handle
                # TerminateJobObject can remove members from accounting before
                # their inherited files close. Retain identity-checked handles,
                # stop members individually, then discover any racing children.
                for handle in held.values():
                    state = self.kernel.WaitForSingleObject(handle, 0)
                    if state == 0:
                        continue
                    if state != 258:
                        return self.cleanup
                    # An exiting process can deny termination before signaling.
                    # Even then, the bounded handle wait below is mandatory.
                    if not self.kernel.TerminateProcess(handle, 1) and ctypes.get_last_error() != 5:
                        return self.cleanup
                for handle in held.values():
                    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                    if self.kernel.WaitForSingleObject(handle, remaining_ms) != 0:
                        return self.cleanup
                if not pids and process.poll() is not None and time.monotonic() < deadline:
                    self.cleanup = "complete"
                    return self.cleanup
                time.sleep(min(POLL, max(0, deadline - time.monotonic())))
        finally:
            if self.cleanup != "complete":
                # Best-effort containment on failure is not completion evidence.
                self.kernel.TerminateJobObject(self.job, 1)
            for handle in owned:
                self.kernel.CloseHandle(handle)
        return self.cleanup

    def stop(self, grace: float) -> str:
        process = self.process
        if process is None:
            return self.cleanup
        deadline = time.monotonic() + grace
        if os.name == "nt":
            return self._stop_windows(deadline)
        else:
            # Darwin reports EPERM for a group whose remaining members are
            # zombies awaiting reaping. EPERM never proves the group is gone,
            # so only ESRCH completes cleanup; otherwise the deadline decides.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                self.cleanup = "complete"
                return self.cleanup
            except PermissionError:
                pass
            while time.monotonic() < deadline:
                process.poll()
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    self.cleanup = "complete"
                    return self.cleanup
                except PermissionError:
                    pass
                if time.monotonic() + 0.1 >= deadline:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                time.sleep(POLL)
        process.poll()
        self.cleanup = "incomplete"
        return self.cleanup

    def close(self) -> None:
        if self.job is not None:
            self.kernel.CloseHandle(self.job)
            self.job = None


class NativeEvents:
    """Recognize only native emitted fields; never infer tokens from characters."""

    def __init__(self, host: str, asg_server: str) -> None:
        self.host = host
        self.asg_server = asg_server
        self.events = 0
        self.malformed = 0
        self.terminal: str | None = None
        self.terminal_at_ns: int | None = None
        self.final_text: str | None = None
        self.session_id: str | None = None
        self.model: str | None = None
        self.host_version: str | None = None
        self.calls: dict[str, dict] = {}
        self.tool_ids: set[str] = set()
        self.token_rows: list[dict] = []
        self.result_usage: dict | None = None
        self.permission_denials: int | None = None
        self.errors = 0
        self.error_item_ids: set[str] = set()
        self.fallback_metadata_warnings = 0
        self.fallback_metadata_item_ids: set[str] = set()
        self.fallback_metadata_digest: str | None = None
        self.native_is_error = False
        self.num_turns: int | None = None
        self.statuses: set[str] = set()

    def feed(self, event: Any, observed_at_ns: int) -> None:
        if not isinstance(event, dict):
            self.malformed += 1
            return
        self.events += 1
        kind = event.get("type")
        if not isinstance(kind, str):
            self.malformed += 1
            return
        if self.host == "claude-code":
            if kind == "system" and event.get("subtype") == "init":
                self.session_id = event.get("session_id") if isinstance(event.get("session_id"), str) else None
                self.model = event.get("model") if isinstance(event.get("model"), str) else None
                self.host_version = event.get("claude_code_version")
            if kind == "assistant":
                message = event.get("message", {})
                if isinstance(message, dict):
                    usage = message.get("usage")
                    if isinstance(usage, dict):
                        self.token_rows.append(usage)
                    for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            self._tool(block.get("id"), block.get("name"), block.get("input"), "started")
            if kind == "result":
                subtype = event.get("subtype")
                self.terminal = subtype if subtype in {
                    "success", "error_max_turns", "error_during_execution", "error_max_budget_usd",
                    "error_max_structured_output_retries"
                } else "unknown_result"
                self.terminal_at_ns = observed_at_ns
                self.final_text = event.get("result") if isinstance(event.get("result"), str) else None
                if isinstance(event.get("usage"), dict):
                    self.result_usage = event["usage"]
                if isinstance(event.get("permission_denials"), list):
                    self.permission_denials = len(event["permission_denials"])
                self.native_is_error = event.get("is_error") is True
                self.num_turns = event.get("num_turns") if nonnegative(event.get("num_turns")) else None
                if self.native_is_error:
                    self.errors += 1
        else:
            if kind == "thread.started" and isinstance(event.get("thread_id"), str):
                self.session_id = event["thread_id"]
            if kind in {"item.started", "item.updated", "item.completed"}:
                item = event.get("item")
                if isinstance(item, dict):
                    item_type = item.get("type")
                    if not isinstance(item_type, str):
                        self.malformed += 1
                        return
                    if kind == "item.completed" and item_type == "agent_message" and isinstance(item.get("text"), str):
                        self.final_text = item["text"]
                    if kind == "item.completed" and item_type == "error":
                        key = item.get("id")
                        digest = sha_bytes(key.encode("utf-8", errors="surrogatepass")) if isinstance(key, str) and key else None
                        warning = self._fallback_metadata_warning(item.get("message"))
                        seen = self.fallback_metadata_item_ids if warning else self.error_item_ids
                        # Missing identity cannot prove a duplicate or an error-free turn.
                        if digest is None or digest not in seen:
                            if warning:
                                self.fallback_metadata_warnings += 1
                            else:
                                self.errors += 1
                            if digest is not None:
                                seen.add(digest)
                    if item_type == "mcp_tool_call":
                        key = item.get("id")
                        if isinstance(key, str):
                            self.tool_ids.add(key)
                            if item.get("server") == self.asg_server:
                                self.calls[key] = {"tool": item.get("tool"), "arguments": item.get("arguments"),
                                                   "native_status": item.get("status"), "completed": kind == "item.completed"}
                    elif item_type in {"command_execution", "web_search", "file_change"} and isinstance(item.get("id"), str):
                        self.tool_ids.add(item["id"])
            if kind in {"turn.completed", "turn.failed"}:
                self.terminal = kind
                self.terminal_at_ns = observed_at_ns
                # Cumulative snapshots must not be summed or reuse stale usage.
                usage = event.get("usage")
                self.token_rows = [usage] if isinstance(usage, dict) else []
            if kind in {"error", "turn.failed"}:
                self.errors += 1
        if isinstance(kind, str) and kind in {"turn.started", "turn.completed", "turn.failed", "error", "result"}:
            self.statuses.add(kind)

    def _fallback_metadata_warning(self, message: Any) -> bool:
        """Match codex-cli's exact fallback-metadata text, one distinct text per capture.

        The model token must be nonempty, single-line and free of backticks, so no
        extra text or second message can hide inside it. A later text naming another
        model is a distinct message and remains an error.
        """
        if not isinstance(message, str):
            return False
        token_end = len(message) - len(FALLBACK_METADATA_SUFFIX)
        if (token_end <= len(FALLBACK_METADATA_PREFIX) or not message.startswith(FALLBACK_METADATA_PREFIX)
                or not message.endswith(FALLBACK_METADATA_SUFFIX)):
            return False
        token = message[len(FALLBACK_METADATA_PREFIX):token_end]
        # splitlines() covers every line boundary, not only LF.
        if "`" in token or token.splitlines() != [token]:
            return False
        digest = sha_bytes(message.encode("utf-8", errors="surrogatepass"))
        if self.fallback_metadata_digest is None:
            self.fallback_metadata_digest = digest
        return digest == self.fallback_metadata_digest

    def _tool(self, key: Any, name: Any, arguments: Any, status: str) -> None:
        if not isinstance(key, str) or not isinstance(name, str):
            return
        self.tool_ids.add(key)
        prefix = "mcp__" + self.asg_server + "__"
        if name.startswith(prefix):
            self.calls[key] = {"tool": name[len(prefix):], "arguments": arguments,
                               "native_status": status, "completed": False}

    def tokens(self, complete: bool) -> dict:
        mapping = {
            "model_input_tokens": "input_tokens", "model_output_tokens": "output_tokens",
            "model_cache_read_tokens": "cache_read_input_tokens" if self.host == "claude-code" else "cached_input_tokens",
            "model_cache_write_tokens": "cache_creation_input_tokens" if self.host == "claude-code" else "cache_write_input_tokens",
            "model_total_tokens": "total_tokens",
        }
        rows = [self.result_usage] if self.result_usage is not None else self.token_rows
        method = self.host + "-native-usage-"
        if self.host == "codex":
            # Complete stdout does not bind cumulative thread usage to this turn.
            method = "codex-stdout-thread-cumulative-usage-"
        result = {}
        for target, field in mapping.items():
            values = [row.get(field) for row in rows]
            if values and all(nonnegative(value) for value in values):
                usage_complete = (complete and self.terminal is not None
                                  and self.host == "claude-code" and self.result_usage is not None)
                result[target] = measured(sum(values), "tokens", method + field, usage_complete)
            else:
                result[target] = unavailable()
        return result


class EventTail:
    def __init__(self, path: Path, native: NativeEvents) -> None:
        self.path = path
        self.native = native
        self.offset = 0
        self.pending = b""
        self.discarding = False

    def poll(self, final: bool = False) -> None:
        with self.path.open("rb", buffering=0) as handle:
            handle.seek(self.offset)
            # Snapshot a bounded prefix so a continuously writing child cannot
            # keep this poll inside the parser past the process deadline.
            remaining = min(max(0, self.path.stat().st_size - self.offset), CHUNK * 4)
            while remaining:
                chunk = handle.read(min(CHUNK, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                self.offset += len(chunk)
                self.pending += chunk
                while b"\n" in self.pending:
                    line, self.pending = self.pending.split(b"\n", 1)
                    if not self.discarding:
                        self._line(line)
                    self.discarding = False
                if len(self.pending) > MAX_FRAME:
                    self.native.malformed += 1
                    self.pending = b""
                    self.discarding = True
        if final and self.offset == self.path.stat().st_size and self.pending and not self.discarding:
            self._line(self.pending)
            self.pending = b""

    def _line(self, line: bytes) -> None:
        if not line.strip():
            return
        if len(line) > MAX_FRAME:
            self.native.malformed += 1
            return
        try:
            self.native.feed(json.loads(line), time.monotonic_ns())
        except (ValueError, UnicodeError, TypeError, KeyError):
            self.native.malformed += 1


class FrameReader:
    """Side observation of exact JSONL/Content-Length frames; no forwarding role."""

    def __init__(self, callback: Any) -> None:
        self.callback = callback
        self.pending = b""
        self.offset = 0
        self.invalid = 0
        self.disabled = False

    def feed(self, data: bytes, at_ns: int) -> None:
        if self.disabled:
            return
        self.pending += data
        while self.pending:
            if self.pending[:15].lower() == b"content-length:":
                end = self.pending.find(b"\r\n\r\n")
                if end < 0:
                    if len(self.pending) > CHUNK:
                        self._disable()
                    return
                try:
                    headers = self.pending[:end].split(b"\r\n")
                    lengths = [int(row.split(b":", 1)[1].strip()) for row in headers
                               if row.split(b":", 1)[0].lower() == b"content-length"]
                    if len(lengths) != 1 or not 0 <= lengths[0] <= MAX_FRAME:
                        raise ValueError
                except ValueError:
                    self._disable()
                    return
                size = end + 4 + lengths[0]
                if len(self.pending) < size:
                    return
                body = self.pending[end + 4:size]
            elif b"content-length:".startswith(self.pending.lower()) and len(self.pending) < 15:
                return
            else:
                end = self.pending.find(b"\n")
                if end < 0:
                    if len(self.pending) > MAX_FRAME:
                        self._disable()
                    return
                size = end + 1
                body = self.pending[:end].rstrip(b"\r")
            raw = self.pending[:size]
            self.pending = self.pending[size:]
            start = self.offset
            self.offset += size
            try:
                event = json.loads(body)
            except (ValueError, UnicodeError):
                self.invalid += 1
                continue
            self.callback(event, start, size, sha_bytes(raw), at_ns)

    def _disable(self) -> None:
        self.invalid += 1
        self.disabled = True
        self.pending = b""

    def complete(self) -> bool:
        return not self.disabled and not self.pending and self.invalid == 0


def request_key(value: Any) -> str | None:
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return json.dumps(value, ensure_ascii=False)
    return None


def safe_request_scope(arguments: Any) -> tuple[dict, bool]:
    """Copy only constrained filter metadata, never arbitrary query/IDs/paths."""
    if not isinstance(arguments, dict):
        return {}, False
    safe = {}
    valid = True
    providers = arguments.get("providers")
    if providers is not None:
        if isinstance(providers, list) and all(isinstance(p, str) and p in {"claude-code", "codex"} for p in providers):
            safe["providers"] = providers
        else:
            valid = False
    repo = arguments.get("repo")
    if repo is not None:
        if isinstance(repo, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) and len(repo) <= 255:
            safe["repo"] = repo
        else:
            valid = False
    for field in ("since", "until"):
        value = arguments.get(field)
        if value is not None:
            if isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9]{2}:[0-9]{2})", value):
                safe[field] = value
            else:
                valid = False
    for field in ("include_system", "group_by_session"):
        if isinstance(arguments.get(field), bool):
            safe[field] = arguments[field]
    for field, allowed in (("sidechain", {"include", "main_only", "subagent_only"}),
                           ("tool_kind", {"file", "command", "web", "query", "unknown"})):
        value = arguments.get(field)
        if isinstance(value, str) and value in allowed:
            safe[field] = value
    return safe, valid


class WireCapture:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.lock = threading.Lock()
        self.files = {direction: exclusive_file(output, direction + ".bin")
                      for direction in ("request", "response")}
        self.log = exclusive_file(output, "wire-events.private.jsonl")
        self.lengths = {"request": 0, "response": 0}
        self.forwarded = {"request": 0, "response": 0}
        self.eof = {"request": False, "response": False}
        self.errors: list[str] = []
        self.requests: dict[str, dict] = {}
        self.responses: dict[str, dict] = {}
        self.frames: list[dict] = []
        self.sequence = 0
        self.closed = False
        self.frames_overflow = False
        self.protocol_incomplete = False
        self.retained_frame_bytes = 0
        self.readers = {direction: FrameReader(
            lambda event, offset, length, digest, at, direction=direction:
                self._frame(direction, event, offset, length, digest, at)
        ) for direction in self.files}

    def _record(self, event: dict) -> None:
        self.sequence += 1
        event["ordinal"] = self.sequence
        self.log.write(json_bytes(event) + b"\n")
        self.log.flush()

    def _frame(self, direction: str, event: Any, offset: int, length: int, digest: str, at: int) -> None:
        frame = {"direction": direction, "offset": offset, "length": length,
                 "sha256": digest, "monotonic_ns": at, "message": event}
        if len(self.frames) < 4096 and self.retained_frame_bytes + length <= MAX_FRAME * 2:
            self.frames.append(frame)
            self.retained_frame_bytes += length
        else:
            self.frames_overflow = True
        self._record({"kind": "frame", **frame})
        if not isinstance(event, dict) or event.get("jsonrpc") != "2.0":
            self.protocol_incomplete = True
            return
        key = request_key(event.get("id"))
        if direction == "request" and not isinstance(event.get("method"), str):
            self.protocol_incomplete = True
            return
        if direction == "response" and key is not None and (
                "method" in event or (("result" in event) == ("error" in event))):
            self.protocol_incomplete = True
            return
        if key is not None:
            target = self.requests if direction == "request" else self.responses
            if self.frames_overflow:
                return
            if key in target:
                self.errors.append("duplicate_rpc_id")
            target[key] = frame

    def receive(self, direction: str, data: bytes) -> None:
        with self.lock:
            if self.closed:
                return
            at = time.monotonic_ns()
            offset = self.lengths[direction]
            self.files[direction].write(data)
            self.files[direction].flush()
            self.lengths[direction] += len(data)
            self._record({"kind": "received", "direction": direction, "offset": offset,
                          "length": len(data), "sha256": sha_bytes(data), "monotonic_ns": at})
            try:
                self.readers[direction].feed(data, at)
            except (ValueError, TypeError, KeyError):
                # An unknown observational shape never rewrites or filters wire.
                self.errors.append("wire_observation_unavailable")
                self.readers[direction]._disable()

    def sent(self, direction: str, length: int) -> None:
        with self.lock:
            if not self.closed:
                offset = self.forwarded[direction]
                self.forwarded[direction] += length
                self._record({"kind": "forwarded", "direction": direction,
                              "offset": offset, "length": length, "monotonic_ns": time.monotonic_ns()})

    def finish_direction(self, direction: str, error: str | None) -> None:
        with self.lock:
            if self.closed:
                return
            self.eof[direction] = error is None
            if error:
                self.errors.append(error)
            self._record({"kind": "eof" if error is None else "error", "direction": direction,
                          "code": error, "monotonic_ns": time.monotonic_ns()})

    def snapshot(self, tree_complete: bool) -> dict:
        with self.lock:
            complete = tree_complete and all(self.eof.values()) and not self.errors and self.lengths == self.forwarded
            parsed = not self.frames_overflow and all(reader.complete() for reader in self.readers.values())
            trace = []
            for key, request in self.requests.items():
                event = request["message"]
                if event.get("method") != "tools/call":
                    continue
                params = event.get("params")
                params = params if isinstance(params, dict) else {}
                tool = params.get("name")
                tool = tool if isinstance(tool, str) else None
                arguments = params.get("arguments")
                scope, scope_safe = safe_request_scope(arguments)
                arguments = arguments if isinstance(arguments, dict) else {}
                response = self.responses.get(key)
                trace.append({"ordinal": len(trace) + 1, "channel": "mcp",
                              "operation_class": TOOLS.get(tool, "other"),
                              "operation_name": tool if tool in TOOLS else "unknown_asg_tool",
                              "request_scope_observed": scope, "request_limit": arguments.get("limit") if nonnegative(arguments.get("limit")) else None,
                              "request_max_response_bytes": arguments.get("max_bytes") if nonnegative(arguments.get("max_bytes")) else None,
                              "request_sha256": request["sha256"],
                              "response_sha256": response["sha256"] if response else None,
                              "response_received": response is not None,
                              "response_complete": response is not None and complete,
                              "observed_evidence": [], "gap_or_expansion_reason": None})
            return {"complete": complete, "parsed_complete": parsed,
                    "trace_completeness": "complete" if complete and parsed and not self.protocol_incomplete else "partial",
                    "trace": trace, "received_bytes": dict(self.lengths),
                    "forwarded_bytes": dict(self.forwarded), "eof": dict(self.eof),
                    "errors": sorted(set(self.errors)),
                    "frame_count": len(self.frames),
                    "capture_sha256": {direction: sha_file(self.output / (direction + ".bin"), length)
                                       for direction, length in self.lengths.items()}}

    def close(self) -> None:
        with self.lock:
            self.closed = True
            for handle in self.files.values():
                handle.close()
            self.log.close()


def pump_stream(source: BinaryIO, destination: BinaryIO, direction: str,
                capture: WireCapture, done: threading.Event, *, close_destination: bool) -> None:
    failure = None
    try:
        while True:
            data = os.read(source.fileno(), CHUNK)
            if not data:
                break
            capture.receive(direction, data)
            view = memoryview(data)
            while view:
                count = os.write(destination.fileno(), view)
                if count <= 0:
                    raise OSError("write_failed")
                capture.sent(direction, count)
                view = view[count:]
            destination.flush()
    except (OSError, ValueError):
        failure = "forwarding_io_failed"
    finally:
        if close_destination:
            try:
                destination.close()
            except OSError:
                failure = "forwarding_close_failed"
        capture.finish_direction(direction, failure)
        done.set()


def proxy_stdio(command: Sequence[str], *, expected_executable_sha256: str,
                workdir: Path, output_root: Path, run_id: str, timeout_seconds: float,
                input_stream: BinaryIO | None = None, output_stream: BinaryIO | None = None,
                environment: Mapping[str, str] | None = None, cleanup_seconds: float = 1.0) -> dict:
    command = checked_argv(command)
    if not HASH.fullmatch(expected_executable_sha256) or sha_file(Path(command[0])) != expected_executable_sha256:
        raise CaptureError("asg_executable_digest_mismatch")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or not 0 < cleanup_seconds <= 10:
        raise CaptureError("invalid_time_budget")
    workdir = checked_directory(workdir)
    output = create_output(output_root, run_id)
    input_stream = input_stream if input_stream is not None else sys.stdin.buffer
    output_stream = output_stream if output_stream is not None else sys.stdout.buffer
    if os.name == "nt":
        import msvcrt
        for stream in (input_stream, output_stream):
            msvcrt.setmode(stream.fileno(), os.O_BINARY)
    capture = WireCapture(output)
    tree = ProcessTree()
    started = time.monotonic_ns()
    timeout = False
    error_code = None
    process = None
    done_in, done_out = threading.Event(), threading.Event()
    try:
        with exclusive_file(output, "stderr.private.bin") as stderr:
            process = tree.spawn(command, cwd=workdir, env=None if environment is None else dict(environment),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0)
            assert process.stdin and process.stdout
            threads = [threading.Thread(target=pump_stream, args=(input_stream, process.stdin, "request", capture, done_in),
                                        kwargs={"close_destination": True}, daemon=True),
                       threading.Thread(target=pump_stream, args=(process.stdout, output_stream, "response", capture, done_out),
                                        kwargs={"close_destination": False}, daemon=True)]
            for thread in threads:
                thread.start()
            deadline = started / 1_000_000_000 + timeout_seconds
            while True:
                native_exit = process.poll()
                now = time.monotonic()
                # Admission and forwarding share the original launch budget.
                # A completed process observed after it expires is still a timeout.
                if now >= deadline:
                    timeout = True
                    break
                if native_exit is not None and done_out.is_set():
                    break
                time.sleep(min(POLL, deadline - now))
            cleanup = tree.stop(cleanup_seconds)
            for thread in threads:
                thread.join(timeout=0.1)
            if process.stdout and done_out.is_set():
                process.stdout.close()
            if process.stdin and done_in.is_set() and not process.stdin.closed:
                process.stdin.close()
    except (OSError, CaptureError, KeyboardInterrupt) as error:
        error_code = (str(error) if isinstance(error, CaptureError) else
                      "capture_interrupted" if isinstance(error, KeyboardInterrupt) else "proxy_spawn_or_io_failed")
        cleanup = tree.stop(cleanup_seconds)
    finally:
        ended = time.monotonic_ns()
        tree.close()
    try:
        state = capture.snapshot(cleanup == "complete" and not timeout and error_code is None)
    finally:
        capture.close()
    complete = state["complete"] and not timeout and error_code is None
    native_code = process.poll() if process else None
    measurements = {"asg_request_bytes": measured(state["received_bytes"]["request"], "bytes", "transparent-stdio-wire", complete),
                    "asg_response_bytes": measured(state["received_bytes"]["response"], "bytes", "transparent-stdio-wire", complete),
                    "asg_total_bytes": measured(sum(state["received_bytes"].values()), "bytes", "transparent-stdio-wire", complete)}
    summary = {"schema": SCHEMA, "mode": "proxy", "execution_state": "failed" if timeout or error_code or state["errors"] or native_code != 0 else "completed",
               "timed_out": timeout, "native_returncode": native_code,
               "cleanup": cleanup, "error_code": error_code, "transparent": True,
               "executable_sha256": expected_executable_sha256, "started_monotonic_ns": started,
               "ended_monotonic_ns": ended, "wire": state, "transport": measurements,
               "acceptance": "open"}
    write_json(output, "proxy-summary.json", summary)
    return summary


def _safe_identity(value: Any) -> str | None:
    return value if isinstance(value, str) and IDENTIFIER.fullmatch(value) else None


def _host_trace(native: NativeEvents) -> list[dict]:
    trace = []
    for call in native.calls.values():
        tool = call.get("tool")
        tool = tool if isinstance(tool, str) else None
        scope, _ = safe_request_scope(call.get("arguments"))
        arguments = call.get("arguments")
        arguments = arguments if isinstance(arguments, dict) else {}
        trace.append({"ordinal": len(trace) + 1, "channel": "mcp",
                      "operation_class": TOOLS.get(tool, "other"),
                      "operation_name": tool if tool in TOOLS else "unknown_asg_tool",
                      "request_scope_observed": scope, "request_limit": arguments.get("limit") if nonnegative(arguments.get("limit")) else None,
                      "request_max_response_bytes": arguments.get("max_bytes") if nonnegative(arguments.get("max_bytes")) else None,
                      "request_sha256": None,
                      "response_sha256": None, "response_received": call.get("completed") is True,
                      "response_complete": False, "observed_evidence": [],
                      "gap_or_expansion_reason": None})
    return trace


def run_host(host: str, command: Sequence[str], *, profile_dir: Path, workdir: Path,
             prompt: bytes, output_root: Path, run_id: str, timeout_seconds: float,
             settings: Path | None = None, mcp_config: Path | None = None,
             config_profile: str | None = None, model: str | None = None,
             max_turns: int | None = None, asg_server: str = "agent-session-grep",
             environment: Mapping[str, str] | None = None,
             completion_grace_seconds: float = DEFAULT_COMPLETION_GRACE_SECONDS, cleanup_seconds: float = 1.0,
             max_log_bytes: int = 256 * 1024 * 1024) -> dict:
    if not isinstance(prompt, bytes) or len(prompt) > MAX_FRAME:
        raise CaptureError("invalid_prompt_bytes")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or not 0 < cleanup_seconds <= 10:
        raise CaptureError("invalid_time_budget")
    if not math.isfinite(completion_grace_seconds) or completion_grace_seconds < 0 or max_log_bytes < CHUNK:
        raise CaptureError("invalid_capture_budget")
    if not IDENTIFIER.fullmatch(asg_server):
        raise CaptureError("invalid_asg_server_name")
    profile = checked_directory(profile_dir)
    workdir = checked_directory(workdir)
    argv = host_argv(host, command, workdir, settings=settings, mcp_config=mcp_config,
                     config_profile=config_profile, model=model, max_turns=max_turns)
    output = create_output(output_root, run_id)
    child_env = profile_environment(host, profile, environment)
    native = NativeEvents(host, asg_server)
    tail = EventTail(output / "stdout.private.jsonl", native)
    tree = ProcessTree()
    started = time.monotonic_ns()
    timed_out = False
    stalled = False
    error_code = None
    returncode_at_stop = None
    stopped = started
    process = None
    reason = "native_exit"
    with ExitStack() as stack:
        stdin = stack.enter_context(exclusive_file(output, "prompt.private.bin"))
        stdin.write(prompt)
        stdin.flush()
        stdin.close()
        input_file = stack.enter_context((output / "prompt.private.bin").open("rb", buffering=0))
        stdout = stack.enter_context(exclusive_file(output, "stdout.private.jsonl"))
        stderr = stack.enter_context(exclusive_file(output, "stderr.private.bin"))
        # Raw argv stays private and contains no inherited environment snapshot.
        write_json(output, "launch.private.json", {"host": host, "argv": argv,
                   "profile_dir": str(profile), "workdir": str(workdir)})
        try:
            process = tree.spawn(argv, cwd=workdir, env=child_env, stdin=input_file,
                                 stdout=stdout, stderr=stderr, bufsize=0)
            deadline = started + int(timeout_seconds * 1_000_000_000)
            while True:
                tail.poll()
                returncode_at_stop = process.poll()
                current = time.monotonic_ns()
                # Observation shares the original budget, even for a zero exit.
                if current >= deadline:
                    timed_out = True
                    reason = "time_budget"
                    break
                if native.terminal_at_ns is not None and current - native.terminal_at_ns >= int(completion_grace_seconds * 1_000_000_000):
                    stalled = True
                    reason = "terminal_event_process_stalled"
                    break
                if returncode_at_stop is not None:
                    break
                if sum((output / member).stat().st_size for member in ("stdout.private.jsonl", "stderr.private.bin")) > max_log_bytes:
                    error_code = "native_log_budget_exceeded"
                    reason = "capture_budget"
                    break
                time.sleep(POLL)
        except (OSError, CaptureError) as error:
            error_code = str(error) if isinstance(error, CaptureError) else "host_spawn_or_io_failed"
            reason = "launch_error"
        finally:
            stopped = time.monotonic_ns()
            cleanup = tree.stop(cleanup_seconds)
            tree.close()
            stdout.flush()
            stderr.flush()
            tail.poll(final=True)
    if native.final_text is not None:
        with exclusive_file(output, "final-response.private.txt") as handle:
            handle.write(native.final_text.encode("utf-8"))
    # A regular file avoids inherited-pipe waits; surviving writers or malformed
    # output still prevent claiming complete capture. Snapshot lengths are fixed.
    log_sizes = {member: (output / member).stat().st_size for member in ("stdout.private.jsonl", "stderr.private.bin")}
    complete = (cleanup == "complete" and native.malformed == 0 and tail.offset == log_sizes["stdout.private.jsonl"]
                and not tail.pending and not tail.discarding and error_code is None and not timed_out and not stalled)
    successful_terminal = native.terminal in {"success", "turn.completed"} and not native.native_is_error
    latency_end = native.terminal_at_ns if successful_terminal and native.final_text is not None else stopped
    latency = measured((latency_end - started) / 1_000_000, "milliseconds", "monotonic-prompt-through-native-terminal", complete and successful_terminal)
    latency.update({"start_monotonic_ns": started, "end_monotonic_ns": latency_end})
    if not successful_terminal or native.final_text is None:
        latency = unavailable("not_executed" if process is None else "collector_error")
    trace = _host_trace(native)
    token_metrics = native.tokens(complete)
    state = "completed" if (successful_terminal and native.final_text is not None and not timed_out and error_code is None
                            and returncode_at_stop in {0, None}) else "failed"
    summary = {
        "schema": SCHEMA, "mode": "run", "host": host, "run_id": run_id,
        "execution_state": state, "stop_reason": reason, "timed_out": timed_out,
        "completed_but_stalled": stalled, "native_status": native.terminal,
        "native_returncode_before_cleanup": returncode_at_stop,
        "native_returncode_after_cleanup": process.poll() if process else None,
        "cleanup": cleanup, "cleanup_method": tree.method, "error_code": error_code,
        "capture_complete": complete, "native_event_count": native.events,
        "malformed_native_event_count": native.malformed,
        "session_id_sha256": sha_bytes(native.session_id.encode()) if native.session_id else None,
        "resume_identity": "private-native-stdout-only" if native.session_id else "unavailable",
        "model_identity": _safe_identity(native.model), "host_version": _safe_identity(native.host_version),
        "native_error_count": native.errors,
        "native_fallback_metadata_warning_count": native.fallback_metadata_warnings if host == "codex" else None,
        "native_is_error": native.native_is_error,
        "native_num_turns": native.num_turns,
        "native_permission_denial_count": native.permission_denials,
        "started_monotonic_ns": started, "stopped_monotonic_ns": stopped,
        "prompt_sha256": sha_bytes(prompt),
        "final_response_sha256": sha_bytes(native.final_text.encode()) if native.final_text is not None else None,
        "stdout_prefix_sha256": sha_file(output / "stdout.private.jsonl", log_sizes["stdout.private.jsonl"]),
        "stderr_prefix_sha256": sha_file(output / "stderr.private.bin", log_sizes["stderr.private.bin"]),
        "captured_log_bytes": log_sizes, "asg_trace": trace, "asg_trace_completeness": "partial",
        "measurements": {
            "calls": {"asg_operation_count": measured(len(trace), "count", "native-asg-named-tool-events", False) if trace else unavailable("instrumentation_missing"),
                      "all_host_tool_call_count": measured(len(native.tool_ids), "count", "native-recognized-tool-events", False) if native.tool_ids else unavailable("instrumentation_missing")},
            "tokens": token_metrics,
            "transport": {name: unavailable("transport_not_captured") for name in
                          ("asg_request_bytes", "asg_response_bytes", "asg_total_bytes")},
            "latency": {"end_to_end": latency}},
        "token_counter_semantics": "provider-defined-input-includes-cache" if host == "codex" and token_metrics["model_input_tokens"]["status"] == "observed" else "unknown",
        "acceptance": "open",
    }
    write_json(output, "capture-summary.json", summary)
    return summary


def make_observation(summary: dict, metadata: dict, pack: dict, *, wire: dict | None = None) -> dict:
    """Project capture into the frozen pack schema; correctness stays ungraded.

    The parent supplies already sanitized identity/resolution metadata and the
    original pack. No raw response, inferred provenance or guessed counters is
    copied into a public observation. Incomplete proof stays an open verdict.
    """
    case_id = metadata.get("case_id")
    cases = {case["case_id"]: case for case in pack["cases"]}
    if case_id not in cases or cases[case_id]["host"] != summary["host"]:
        raise CaptureError("observation_case_host_mismatch")
    if metadata.get("repeat_ordinal") not in (1, 2, 3) or metadata.get("description_variant") not in ("baseline", "candidate"):
        raise CaptureError("invalid_observation_repeat_or_variant")
    fields = pack["capture"]["observation_schema"]["properties"]
    observed = {name: None for name in fields}
    identity_fields = ("run_id", "case_id", "repeat_ordinal", "description_variant", "host_version", "model_identity",
                       "model_settings_sha256", "description_sha256", "candidate_archive_sha256",
                       "candidate_manifest_sha256", "candidate_source_identity", "pack_sha256", "corpus_sha256", "case_set_sha256")
    for name in identity_fields:
        value = metadata.get(name)
        if value is not None:
            if name == "repeat_ordinal":
                if value not in (1, 2, 3) or isinstance(value, bool):
                    raise CaptureError("invalid_observation_repeat")
            elif name.endswith("sha256"):
                if not isinstance(value, str) or not HASH.fullmatch(value):
                    raise CaptureError("invalid_observation_digest")
            elif not isinstance(value, str) or PRIVATE_FORM.search(value) or not IDENTIFIER.fullmatch(value):
                raise CaptureError("unsafe_observation_identifier")
            observed[name] = value
    for name in ("policy_epoch", "snapshot_generation"):
        value = metadata.get(name)
        if value is not None and not nonnegative(value):
            raise CaptureError("invalid_observation_counter")
        observed[name] = value
    observed["catalog_incarnation"] = _safe_identity(metadata.get("catalog_incarnation"))
    required_hashes = ("pack_sha256", "corpus_sha256", "case_set_sha256")
    if any(observed[name] is None for name in required_hashes) or not _safe_identity(observed["run_id"]):
        raise CaptureError("observation_identity_required")
    if observed["corpus_sha256"] != pack["determinism"]["corpus_sha256"] or observed["case_set_sha256"] != pack["determinism"]["case_set_sha256"]:
        raise CaptureError("observation_pack_digest_mismatch")
    if metadata.get("source_resolution") or metadata.get("current_session_identity", {}).get("status") == "trusted-host-supplied":
        raise CaptureError("proof_enrichment_requires_parent_adjudication")
    lifecycle = {name: "open" for name in ("installed", "recognized", "loaded", "called", "read_history", "continued")}
    for name, value in metadata.get("lifecycle", {}).items():
        if name not in lifecycle or value not in {"pass", "fail", "open", "not_run", "blocked", "not_applicable"}:
            raise CaptureError("invalid_lifecycle_metadata")
        lifecycle[name] = value
    observed.update({"host": summary["host"], "execution_state": summary["execution_state"],
                     "rendered_host_input_sha256": summary["prompt_sha256"],
                     "source_resolution": [],
                     "current_session_identity": {"status": "unavailable", "canonical_session_id": None,
                                                  "method": "host-identity-not-independently-verified-by-capture"},
                     "final_response_sha256": summary["final_response_sha256"],
                     "continuation_json_observed": None,
                     "lifecycle": lifecycle,
                     "asg_trace_completeness": summary["asg_trace_completeness"],
                     "asg_trace": summary["asg_trace"], "measurements": summary["measurements"],
                     "token_counter_semantics": summary["token_counter_semantics"],
                     "verdicts": {name: "open" for name in fields["verdicts"]["properties"]},
                     "findings": [], "blocker_codes": ["source_proof_and_continuation_require_parent_adjudication"]})
    if wire is not None:
        # A proxy must be explicitly linked to this host launch. Timestamp order
        # alone is not proof that an unrelated proxy spans the episode.
        expected = metadata.get("proxy_executable_sha256")
        if (metadata.get("proxy_linked_run_id") != summary["run_id"] or expected != wire.get("executable_sha256")
                or not isinstance(expected, str) or not HASH.fullmatch(expected)):
            raise CaptureError("proxy_episode_link_required")
        observed["asg_trace"] = wire["wire"]["trace"]
        all_channels = metadata.get("proxy_covers_all_asg_channels") is True
        observed["asg_trace_completeness"] = wire["wire"]["trace_completeness"] if all_channels else "partial"
        observed["measurements"] = json.loads(json.dumps(observed["measurements"]))
        observed["measurements"]["transport"] = json.loads(json.dumps(wire["transport"]))
        if not all_channels:
            for metric in observed["measurements"]["transport"].values():
                if metric.get("status") == "observed":
                    metric["coverage"] = "partial-episode"
        if wire["wire"]["trace_completeness"] == "complete" and metadata.get("proxy_covers_all_asg_channels") is True:
            observed["measurements"]["calls"]["asg_operation_count"] = measured(len(observed["asg_trace"]), "count", "transparent-tools-call-frames", True)
    if observed["asg_trace"]:
        observed["lifecycle"]["called"] = "pass"
    elif cases[case_id]["expected"]["asg_call"] == "forbidden" and observed["asg_trace_completeness"] == "complete" and metadata.get("proxy_covers_all_asg_channels") is True:
        observed["lifecycle"]["called"] = "not_applicable"
        observed["lifecycle"]["read_history"] = "not_applicable"
    return observed


class QuietParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally echoes the invalid value, which can be a private
        # executable/profile path. Only help contains example paths.
        raise CaptureError("invalid_cli_arguments")


def parser() -> argparse.ArgumentParser:
    root = QuietParser(description=__doc__)
    modes = root.add_subparsers(dest="mode", required=True, parser_class=QuietParser)
    run = modes.add_parser("run", help="Capture one parent-authorized isolated native host invocation.")
    run.add_argument("--host", choices=("claude-code", "codex"), required=True)
    run.add_argument("--executable", type=Path, required=True, help="Explicit absolute native executable; shell=False.")
    run.add_argument("--profile-dir", type=Path, required=True, help="Existing isolated directory supplied by the parent; never scanned for credentials.")
    run.add_argument("--working-dir", type=Path, required=True)
    run.add_argument("--prompt-file", type=Path, required=True, help="UTF-8 prompt bytes sent unchanged through a regular stdin file.")
    run.add_argument("--settings", type=Path, help="Existing parent-supplied Claude settings JSON.")
    run.add_argument("--mcp-config", type=Path, help="Existing parent-supplied Claude MCP JSON; only this set is loaded.")
    run.add_argument("--config-profile", help="Existing Codex named config profile in the isolated CODEX_HOME.")
    run.add_argument("--model", help="Explicit model identifier; omitted means the supplied profile decides.")
    run.add_argument("--max-turns", type=int, help="Claude native turn limit; max-turns errors remain errors.")
    run.add_argument("--asg-server", default="agent-session-grep", help="Exact registered ASG server name for native trace recognition.")
    run.add_argument("--completion-grace-seconds", type=float, default=DEFAULT_COMPLETION_GRACE_SECONDS)
    run.add_argument("--max-log-bytes", type=int, default=256 * 1024 * 1024)
    run.add_argument("--pack", type=Path, help="Original frozen pack, read-only.")
    run.add_argument("--observation-metadata", type=Path, help="Parent-supplied sanitized case/repeat/variant and digest JSON.")
    run.add_argument("--proxy-summary", type=Path, help="Optional finalized proxy summary explicitly linked by metadata to this episode; no automatic all-channel assumption.")
    proxy = modes.add_parser("proxy", help="Transparent binary stdio wrapper around a verified installed ASG command.")
    proxy.add_argument("--command-argv-file", type=Path, required=True, help="Private JSON array: verified executable followed by exact installed argv.")
    proxy.add_argument("--executable-sha256", required=True, help="Expected SHA256 of the installed executable, required before spawn.")
    proxy.add_argument("--working-dir", type=Path, required=True)
    for child in (run, proxy):
        child.add_argument("--output-root", type=Path, required=True, help="Existing ignored/external private directory; no recursive deletion or overwriting.")
        child.add_argument("--run-id", required=True, help="New path-free run identifier. Existing run directory is refused.")
        child.add_argument("--timeout-seconds", type=float, required=True)
        child.add_argument("--cleanup-seconds", type=float, default=1.0)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.mode == "proxy":
            command = bounded_json(args.command_argv_file)
            if not isinstance(command, list):
                raise CaptureError("command_json_array_required")
            summary = proxy_stdio(command, expected_executable_sha256=args.executable_sha256,
                                  workdir=args.working_dir, output_root=args.output_root,
                                  run_id=args.run_id, timeout_seconds=args.timeout_seconds,
                                  cleanup_seconds=args.cleanup_seconds)
            # stdout is exclusively MCP bytes. All capture status lives on disk.
            native_code = summary["native_returncode"]
            if isinstance(native_code, int) and native_code != 0:
                return native_code if native_code >= 0 else 1
            if (summary["timed_out"] or summary["error_code"] or not summary["wire"]["complete"]
                    or summary["wire"]["trace_completeness"] != "complete"):
                return 10
            return 0
        prompt_file = checked_file(args.prompt_file)
        if prompt_file.stat().st_size > MAX_FRAME:
            raise CaptureError("prompt_file_too_large")
        pack = metadata = None
        if bool(args.pack) != bool(args.observation_metadata):
            raise CaptureError("pack_and_metadata_required_together")
        if args.pack:
            pack = bounded_json(args.pack)
            metadata = bounded_json(args.observation_metadata)
            if not isinstance(pack, dict) or not isinstance(metadata, dict):
                raise CaptureError("invalid_observation_inputs")
            if metadata.get("pack_sha256") != sha_file(checked_file(args.pack)):
                raise CaptureError("frozen_pack_digest_mismatch")
        summary = run_host(args.host, [str(args.executable)], profile_dir=args.profile_dir,
                           workdir=args.working_dir, prompt=prompt_file.read_bytes(),
                           output_root=args.output_root, run_id=args.run_id,
                           timeout_seconds=args.timeout_seconds, settings=args.settings,
                           mcp_config=args.mcp_config, config_profile=args.config_profile,
                           model=args.model, max_turns=args.max_turns, asg_server=args.asg_server,
                           completion_grace_seconds=args.completion_grace_seconds,
                           cleanup_seconds=args.cleanup_seconds, max_log_bytes=args.max_log_bytes)
        if args.proxy_summary and pack is None:
            raise CaptureError("proxy_observation_metadata_required")
        if pack is not None:
            wire = bounded_json(args.proxy_summary) if args.proxy_summary else None
            observation = make_observation(summary, metadata, pack, wire=wire)
            write_json(checked_directory(args.output_root) / args.run_id, "observation.json", observation)
        # No prompt, native text, session/native IDs, profile paths, env or token
        # counters are printed. Detailed native state and measurements are files.
        print(json.dumps({"schema": SCHEMA, "mode": "run", "run_id": args.run_id,
                          "execution_state": summary["execution_state"],
                          "native_status": summary["native_status"],
                          "timed_out": summary["timed_out"],
                          "completed_but_stalled": summary["completed_but_stalled"],
                          "capture_complete": summary["capture_complete"], "acceptance": "open"}))
        if summary["timed_out"] or summary["completed_but_stalled"] or summary["cleanup"] != "complete":
            return 10
        return 0 if summary["execution_state"] == "completed" else 1
    except KeyboardInterrupt:
        print(json.dumps({"schema": SCHEMA, "error_code": "capture_interrupted"}), file=sys.stderr)
        return 130
    except (CaptureError, OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"schema": SCHEMA, "error_code": "capture_request_failed"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
