"""FUSE-based sandbox — true prevention via filesystem interception.

Mounts a passthrough FUSE overlay that routes all mutating filesystem
operations through the firewall engine *before* they reach the real
filesystem.  If the engine returns DENY the syscall gets -EACCES and
the file is never touched.
"""

from __future__ import annotations

import atexit
import errno
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentfirewall.audit import AuditLogger
    from agentfirewall.engine import Engine

try:
    import fuse  # fusepy
except (ImportError, OSError):
    fuse = None  # type: ignore[assignment]

from agentfirewall.schema import DenyOperation

# Relative prefix that marks the self-protected config directory
_FIREWALL_DIR = ".agentfirewall"


def _require_fusepy() -> None:
    """Raise a helpful error when fusepy is not installed."""
    if fuse is None:
        raise RuntimeError(
            "fusepy is required for the sandbox.  "
            "Install it with:  pip install agentfirewall[sandbox]"
        )


def _default_mountpoint(source: Path) -> Path:
    """Deterministic temp mountpoint derived from the source path."""
    digest = hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / f"agentfirewall-{digest}"


# ── operation → DenyOperation mapping ──────────────────────────

def _op_for_unlink() -> DenyOperation:
    return DenyOperation.DELETE


def _op_for_rmdir() -> DenyOperation:
    return DenyOperation.DELETE


def _op_for_write() -> DenyOperation:
    return DenyOperation.WRITE


def _op_for_chmod() -> DenyOperation:
    return DenyOperation.CHMOD


def _op_for_truncate() -> DenyOperation:
    return DenyOperation.WRITE


def _op_for_rename() -> DenyOperation:
    return DenyOperation.MOVE_OUTSIDE_SANDBOX


# ── FirewallFS ─────────────────────────────────────────────────

class FirewallFS:
    """FUSE passthrough filesystem that evaluates mutating ops against
    the firewall engine.

    Read operations are forwarded directly.  Mutating operations
    (unlink, write, rename, chmod, truncate, rmdir) are evaluated
    first — if the engine denies the action the syscall returns
    ``-EACCES`` and nothing happens on disk.
    """

    use_ns = True

    def __init__(
        self,
        source: Path,
        engine: "Engine",
        audit: "AuditLogger | None" = None,
    ) -> None:
        self._source = source.resolve()
        self._engine = engine
        self._audit = audit
        # Track open file descriptors → whether first-write was already evaluated
        self._fd_evaluated: dict[int, bool] = {}
        self._lock = Lock()

    def __call__(self, op: str, *args):
        """Dispatch FUSE operations by name (required by fusepy)."""
        if not hasattr(self, op):
            raise OSError(errno.EFAULT, "")
        return getattr(self, op)(*args)

    # ── path helpers ────────────────────────────────────────────

    def _real(self, partial: str) -> str:
        """Translate a FUSE-relative path to the real underlying path."""
        if partial.startswith("/"):
            partial = partial[1:]
        return str(self._source / partial)

    def _rel(self, partial: str) -> str:
        """Return the FUSE-relative path (no leading /)."""
        if partial.startswith("/"):
            partial = partial[1:]
        return partial

    def _is_firewall_dir(self, partial: str) -> bool:
        """True when *partial* is inside .agentfirewall/."""
        rel = self._rel(partial)
        return rel == _FIREWALL_DIR or rel.startswith(_FIREWALL_DIR + "/")

    # ── engine evaluation ───────────────────────────────────────

    def _evaluate(self, operation: DenyOperation, partial: str) -> bool:
        """Return True if the operation is allowed, False if denied."""
        from agentfirewall.engine import Verdict

        rel = self._rel(partial)
        result = self._engine.evaluate_file_operation(operation, rel)
        return result.verdict != Verdict.DENY

    # ── FUSE callbacks: metadata / read (passthrough) ───────────

    def getattr(self, path: str, fh: int | None = None) -> dict:
        real = self._real(path)
        st = os.lstat(real)
        attrs = {
            key: getattr(st, key)
            for key in (
                "st_gid", "st_mode",
                "st_nlink", "st_size", "st_uid",
            )
        }
        # use_ns=True: fusepy expects nanosecond ints for time fields
        attrs["st_atime"] = st.st_atime_ns
        attrs["st_mtime"] = st.st_mtime_ns
        attrs["st_ctime"] = st.st_ctime_ns
        return attrs

    def readdir(self, path: str, fh: int | None = None) -> list[str]:
        real = self._real(path)
        entries = [".", ".."]
        entries.extend(os.listdir(real))
        return entries

    def readlink(self, path: str) -> str:
        return os.readlink(self._real(path))

    def statfs(self, path: str) -> dict:
        real = self._real(path)
        stv = os.statvfs(real)
        return {
            key: getattr(stv, key)
            for key in (
                "f_bavail", "f_bfree", "f_blocks", "f_bsize",
                "f_favail", "f_ffree", "f_files", "f_flag",
                "f_frsize", "f_namemax",
            )
        }

    # ── open / read / release ───────────────────────────────────

    def open(self, path: str, flags: int) -> int:
        real = self._real(path)

        # If opening for write on a protected / firewall-dir path, check now
        writing = flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC)
        if writing:
            if self._is_firewall_dir(path):
                raise OSError(errno.EACCES, "")
            if not self._evaluate(_op_for_write(), path):
                raise OSError(errno.EACCES, "")

        fd = os.open(real, flags)
        with self._lock:
            # Mark as already-evaluated if opened for writing
            self._fd_evaluated[fd] = bool(writing)
        return fd

    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, size)

    def release(self, path: str, fh: int) -> None:
        with self._lock:
            self._fd_evaluated.pop(fh, None)
        os.close(fh)

    # ── create ──────────────────────────────────────────────────

    def create(self, path: str, mode: int, fi: int | None = None) -> int:
        if self._is_firewall_dir(path):
            raise OSError(errno.EACCES, "")
        if not self._evaluate(_op_for_write(), path):
            raise OSError(errno.EACCES, "")
        real = self._real(path)
        fd = os.open(real, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with self._lock:
            self._fd_evaluated[fd] = True  # already evaluated at create time
        return fd

    # ── mutating ops: write ─────────────────────────────────────

    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        # First-write-per-handle evaluation
        with self._lock:
            evaluated = self._fd_evaluated.get(fh, False)
        if not evaluated:
            if self._is_firewall_dir(path):
                raise OSError(errno.EACCES, "")
            if not self._evaluate(_op_for_write(), path):
                raise OSError(errno.EACCES, "")
            with self._lock:
                self._fd_evaluated[fh] = True

        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, data)

    def truncate(self, path: str, length: int, fh: int | None = None) -> None:
        if self._is_firewall_dir(path):
            raise OSError(errno.EACCES, "")
        if not self._evaluate(_op_for_truncate(), path):
            raise OSError(errno.EACCES, "")
        real = self._real(path)
        with open(real, "r+b") as f:
            f.truncate(length)

    # ── mutating ops: delete ────────────────────────────────────

    def unlink(self, path: str) -> None:
        if self._is_firewall_dir(path):
            raise OSError(errno.EACCES, "")
        if not self._evaluate(_op_for_unlink(), path):
            raise OSError(errno.EACCES, "")
        os.unlink(self._real(path))

    def rmdir(self, path: str) -> None:
        if self._is_firewall_dir(path):
            raise OSError(errno.EACCES, "")
        if not self._evaluate(_op_for_rmdir(), path):
            raise OSError(errno.EACCES, "")
        os.rmdir(self._real(path))

    # ── mutating ops: rename / chmod ────────────────────────────

    def rename(self, old: str, new: str) -> None:
        if self._is_firewall_dir(old) or self._is_firewall_dir(new):
            raise OSError(errno.EACCES, "")
        if not self._evaluate(_op_for_rename(), old):
            raise OSError(errno.EACCES, "")
        os.rename(self._real(old), self._real(new))

    def chmod(self, path: str, mode: int) -> None:
        if self._is_firewall_dir(path):
            raise OSError(errno.EACCES, "")
        if not self._evaluate(_op_for_chmod(), path):
            raise OSError(errno.EACCES, "")
        os.chmod(self._real(path), mode)

    # ── passthrough helpers (mkdir, symlink, link, utimens) ─────

    def mkdir(self, path: str, mode: int) -> None:
        if self._is_firewall_dir(path):
            raise OSError(errno.EACCES, "")
        os.mkdir(self._real(path), mode)

    def symlink(self, target: str, source: str) -> None:
        if self._is_firewall_dir(source):
            raise OSError(errno.EACCES, "")
        os.symlink(target, self._real(source))

    def link(self, target: str, source: str) -> None:
        if self._is_firewall_dir(source):
            raise OSError(errno.EACCES, "")
        os.link(self._real(target), self._real(source))

    def utimens(self, path: str, times: tuple | None = None) -> None:
        if times is None:
            os.utime(self._real(path))
        else:
            atime_ns, mtime_ns = times
            os.utime(self._real(path), ns=(atime_ns, mtime_ns))

    def access(self, path: str, amode: int) -> int:
        if not os.access(self._real(path), amode):
            raise OSError(errno.EACCES, "")
        return 0


# ── mount / unmount lifecycle ──────────────────────────────────

def mount(
    source: Path,
    engine: "Engine",
    audit: "AuditLogger | None" = None,
    mountpoint: Path | None = None,
    foreground: bool = True,
) -> Path:
    """Mount a FirewallFS FUSE overlay and block until unmounted.

    Args:
        source: The real directory to protect.
        engine: Firewall engine for evaluating operations.
        audit: Optional audit logger.
        mountpoint: Where to mount (auto-generated if None).
        foreground: Run FUSE in foreground (default True).

    Returns:
        The mountpoint path (useful when auto-generated).
    """
    _require_fusepy()

    source = source.resolve()
    if not source.is_dir():
        raise ValueError(f"Source must be a directory: {source}")

    if mountpoint is None:
        mountpoint = _default_mountpoint(source)

    mountpoint.mkdir(parents=True, exist_ok=True)

    fs = FirewallFS(source, engine, audit)

    # Register cleanup
    def _cleanup(*_args) -> None:
        unmount(mountpoint)

    def _signal_cleanup(signum, _frame) -> None:
        # Spawn fusermount as detached subprocess (works even during C FUSE loop)
        try:
            subprocess.Popen(
                ["fusermount", "-u", str(mountpoint)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
        os._exit(0)

    atexit.register(_cleanup)
    signal.signal(signal.SIGTERM, _signal_cleanup)
    signal.signal(signal.SIGINT, _signal_cleanup)

    fuse.FUSE(
        fs,
        str(mountpoint),
        foreground=foreground,
        nothreads=False,
        allow_other=False,
    )

    return mountpoint


def unmount(mountpoint: Path) -> bool:
    """Safely unmount a FUSE mountpoint.

    Returns True if unmount succeeded, False otherwise.
    """
    mountpoint = Path(mountpoint)
    if not mountpoint.exists():
        return False

    try:
        subprocess.run(
            ["fusermount", "-u", str(mountpoint)],
            check=True,
            capture_output=True,
            timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # Try lazy unmount as fallback
        try:
            subprocess.run(
                ["fusermount", "-uz", str(mountpoint)],
                check=True,
                capture_output=True,
                timeout=10,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False


def is_mounted(mountpoint: Path) -> bool:
    """Check if a path is currently a FUSE mount."""
    mountpoint = str(Path(mountpoint).resolve())
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == mountpoint:
                    return True
    except OSError:
        pass
    return False


def run_sandboxed(
    source: Path,
    engine: "Engine",
    command: list[str],
    audit: "AuditLogger | None" = None,
    mountpoint: Path | None = None,
) -> int:
    """Mount FUSE, run a command with CWD inside the mount, then unmount.

    Returns the command's exit code.
    """
    _require_fusepy()

    source = source.resolve()
    if mountpoint is None:
        mountpoint = _default_mountpoint(source)
    mountpoint.mkdir(parents=True, exist_ok=True)

    fs = FirewallFS(source, engine, audit)

    # We need to run FUSE in a background thread while the command runs
    import threading
    import time

    fuse_error: list[Exception] = []

    def _run_fuse() -> None:
        try:
            fuse.FUSE(
                fs,
                str(mountpoint),
                foreground=True,
                nothreads=False,
                allow_other=False,
            )
        except Exception as exc:
            fuse_error.append(exc)

    fuse_thread = threading.Thread(target=_run_fuse, daemon=True)
    fuse_thread.start()

    # Wait for mount to become available (check /proc/mounts only, no stat)
    for _ in range(50):  # up to 5 seconds
        if is_mounted(mountpoint):
            break
        time.sleep(0.1)
    else:
        unmount(mountpoint)
        fuse_thread.join(timeout=5)
        raise RuntimeError("FUSE mount did not become available")

    try:
        # Use a wrapper shell to cd inside the child process.
        # We must NOT pass cwd=mountpoint to subprocess.run because that
        # triggers stat/chdir on the FUSE mount from the parent process,
        # which can deadlock with the FUSE thread in the same process.
        mp_str = str(mountpoint)
        wrapped = f'cd {mp_str!r} && exec "$@"'
        result = subprocess.run(
            ["bash", "-c", wrapped, "--"] + command,
        )
        return result.returncode
    finally:
        unmount(mountpoint)
        fuse_thread.join(timeout=5)
        if fuse_error:
            raise fuse_error[0]
