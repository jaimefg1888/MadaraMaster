#!/usr/bin/env python3
# Motor asíncrono de borrado — v6.0
# jaimefg1888
#
# Mitigaciones forenses de bajo nivel añadidas en v6:
#   1. Destrucción de metadatos de inodo (MFT / ext4 Journal)
#      — MAC times → epoch 0 + renombrado múltiple con UUIDs de longitud
#        variable para machacar registros de nombre en la MFT/Journal.
#   2. Direct I/O (bypass absoluto de la caché de páginas del SO)
#      — Linux : os.O_DIRECT | os.O_SYNC con buffers alineados a 4 096 B.
#      — Windows: FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING vía
#        ctypes + msvcrt.open_osfhandle.
#      — Fallback automático a I/O normal si el FS rechaza O_DIRECT
#        (FAT32, exFAT, tmpfs, etc.).
#   3. Destrucción de Slack Space y Alternate Data Streams
#      — Slack Space: sobrescribe hasta el límite del clúster físico
#        (ceil(st_size / 4096) * 4096) para eliminar basura residual.
#      — ADS (Windows únicamente): enumera con FindFirstStreamW /
#        FindNextStreamW y machaca cada flujo antes de borrar el archivo.

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import math
import os
import platform
import random
import stat
import string
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Coroutine, Optional

import aiofiles

from audit import AuditLogger
from storage import SanitizationStandard, StorageType, detect_storage_type
from trim import send_trim

# ─── Alignment constants ─────────────────────────────────────────────────────
_SECTOR_SIZE = 4096  # Required alignment for O_DIRECT / NO_BUFFERING
_CLUSTER_SIZE = 4096  # Default cluster size used for slack-space calculation

# ─── Windows flags ───────────────────────────────────────────────────────────
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_FILE_FLAG_NO_BUFFERING = 0x20000000
_GENERIC_WRITE = 0x40000000
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE: int = ctypes.c_void_p(-1).value


# ══════════════════════════════════════════════════════════════════════════════
# Generic helpers
# ══════════════════════════════════════════════════════════════════════════════


def _ensure_writable(path: Path) -> None:
    """Remove the read-only flag from *path* if set.

    Silently ignores errors (e.g. immutable flag set by ``chattr +i``).

    Args:
        path: File whose permissions should be checked.
    """
    try:
        mode = path.stat().st_mode
        if not (mode & stat.S_IWRITE):
            os.chmod(path, mode | stat.S_IWRITE)
    except OSError:
        pass


def _aligned_size(n: int, alignment: int = _SECTOR_SIZE) -> int:
    """Round *n* up to the nearest multiple of *alignment*.

    Args:
        n: Value to round up.
        alignment: Alignment boundary.

    Returns:
        Smallest multiple of *alignment* that is ≥ *n*.
    """
    return math.ceil(n / alignment) * alignment


def _random_name(length: int) -> str:
    """Generate a random lowercase-alphanumeric filename with a ``.tmp`` suffix.

    Args:
        length: Number of random characters before the extension.

    Returns:
        A string such as ``"a3kfzq19wxbm.tmp"``.
    """
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length)) + ".tmp"


# ══════════════════════════════════════════════════════════════════════════════
# 1. Inode-metadata destruction  (MFT / ext4 Journal)
# ══════════════════════════════════════════════════════════════════════════════


def _destroy_metadata(path: Path) -> Path:
    """Erase the file's forensic footprint in the filesystem journal / MFT.

    Performs two operations:

    1. **Timestamp zeroing** — sets ``atime`` and ``mtime`` to Unix epoch 0.
       Most forensic tools (Autopsy, Sleuth Kit) rely on MAC times to
       reconstruct file activity; zeroing them removes this evidence.

    2. **Multi-rename** — renames the file 3–5 times using names of
       variable length (8–24 characters).  Each rename overwrites a
       directory-entry record in the ext4 journal or an MFT file-name
       attribute on NTFS, making the original filename harder to recover.
       After each rename the timestamps are zeroed again because some
       filesystems update ``ctime`` on ``rename(2)``.

    Args:
        path: Path to the file whose metadata should be destroyed.

    Returns:
        The final path of the file after all renames.  May equal *path* if
        every rename attempt failed.
    """
    try:
        os.utime(path, times=(0, 0))
    except OSError:
        pass

    current = path
    n_renames = random.randint(3, 5)
    dir_parent = path.parent

    for _ in range(n_renames):
        length = random.choice([8, 16, 12, 24, 10])
        new_name = dir_parent / _random_name(length)
        try:
            current.rename(new_name)
            try:
                os.utime(new_name, times=(0, 0))
            except OSError:
                pass
            current = new_name
        except OSError:
            break  # Leave the file in its current location if rename fails

    return current


# ══════════════════════════════════════════════════════════════════════════════
# 2. Direct I/O  — OS page-cache bypass
# ══════════════════════════════════════════════════════════════════════════════


class _DirectIOContext:
    """Async write context that bypasses the OS page cache.

    Exposes the same minimal interface as an ``aiofiles`` file object
    (``seek`` / ``write`` / ``flush`` / ``fileno`` / ``close``) so the
    overwrite loop can use it transparently regardless of whether true
    Direct I/O is active.

    All blocking calls are dispatched to a thread pool via
    ``asyncio.to_thread`` to avoid stalling the event loop.

    Attributes:
        direct: ``True`` if the file was opened with ``O_DIRECT`` /
            ``FILE_FLAG_NO_BUFFERING``.  ``False`` if the fallback buffered
            I/O path is active.
        closed: ``True`` after :meth:`close` has been called.
    """

    def __init__(self, fd: int, direct: bool) -> None:
        self._fd = fd
        self.direct = direct
        self.closed = False

    async def seek(self, offset: int) -> None:
        await asyncio.to_thread(os.lseek, self._fd, offset, os.SEEK_SET)

    async def write(self, data: bytes) -> int:
        return await asyncio.to_thread(os.write, self._fd, data)

    async def flush(self) -> None:
        await asyncio.to_thread(os.fsync, self._fd)

    def fileno(self) -> int:
        return self._fd

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await asyncio.to_thread(os.close, self._fd)

    async def __aenter__(self) -> "_DirectIOContext":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


def _open_direct_linux(path: Path) -> tuple[int, bool]:
    """Open *path* with ``O_DIRECT | O_SYNC`` on Linux.

    ``O_DIRECT`` instructs the kernel to bypass the page cache for both
    reads and writes, ensuring that wiped data is committed directly to the
    storage device without lingering in RAM.  ``O_SYNC`` additionally
    guarantees that each ``write(2)`` call blocks until the data reaches
    stable storage.

    If the underlying filesystem does not support ``O_DIRECT`` (FAT32,
    exFAT, tmpfs, CIFS, and others return ``EINVAL`` or ``EOPNOTSUPP``),
    the function falls back to plain ``O_WRONLY`` and returns
    ``direct=False``.

    Args:
        path: File to open.

    Returns:
        A ``(fd, direct)`` tuple where *direct* indicates whether
        ``O_DIRECT`` is active.
    """
    # O_DIRECT may not be defined on all kernel ports; 0x4000 is the
    # canonical value on x86/x86-64 Linux.
    o_direct: int = getattr(os, "O_DIRECT", 0x4000)
    flags_direct = os.O_WRONLY | os.O_SYNC | o_direct

    try:
        fd = os.open(str(path), flags_direct)
        return fd, True
    except OSError:
        # Fallback: filesystem rejects O_DIRECT (FAT32, CIFS, tmpfs, etc.)
        fd = os.open(str(path), os.O_WRONLY)
        return fd, False


def _open_direct_windows(path: Path) -> tuple[int, bool]:
    """Open *path* with ``FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING``.

    These two flags together replicate the effect of ``O_DIRECT | O_SYNC``
    on Linux:

    * ``FILE_FLAG_NO_BUFFERING`` disables the Windows cache manager so
      writes go directly to the disk controller's buffer.
    * ``FILE_FLAG_WRITE_THROUGH`` ensures the disk controller flushes its
      own buffer before reporting write completion.

    The Win32 ``HANDLE`` is converted to a CRT file descriptor via
    ``msvcrt.open_osfhandle`` so the rest of the code can use standard
    ``os.write`` / ``os.lseek`` calls.

    Falls back to a plain ``O_WRONLY | O_BINARY`` descriptor on failure.

    Args:
        path: File to open.

    Returns:
        A ``(fd, direct)`` tuple.
    """
    try:
        import msvcrt

        k32 = ctypes.windll.kernel32
        handle = k32.CreateFileW(
            str(path),
            _GENERIC_WRITE,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_WRITE_THROUGH | _FILE_FLAG_NO_BUFFERING,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            raise OSError("CreateFileW falló")
        fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        return fd, True
    except Exception:
        fd = os.open(str(path), os.O_WRONLY | os.O_BINARY)
        return fd, False


async def _open_direct(path: Path) -> _DirectIOContext:
    """Unified entry point: open *path* with Direct I/O where supported.

    Dispatches to the platform-specific opener in a thread pool and wraps
    the result in a :class:`_DirectIOContext`.  The context transparently
    falls back to buffered I/O when Direct I/O is not available, so callers
    do not need to handle the distinction.

    Args:
        path: File to open for writing.

    Returns:
        An async context manager ready for writing.
    """

    def _open_sync() -> tuple[int, bool]:
        sys_name = platform.system().lower()
        if sys_name == "linux":
            return _open_direct_linux(path)
        if sys_name == "windows":
            return _open_direct_windows(path)
        # macOS: O_DIRECT does not exist.  F_NOCACHE via fcntl is the
        # equivalent, but it requires IOKit bindings.  Use plain O_WRONLY.
        fd = os.open(str(path), os.O_WRONLY)
        return fd, False

    fd, direct = await asyncio.to_thread(_open_sync)
    return _DirectIOContext(fd, direct)


def _make_aligned_buffer(data: bytes) -> bytes:
    """Pad *data* to a multiple of :data:`_SECTOR_SIZE` with zero bytes.

    ``O_DIRECT`` / ``FILE_FLAG_NO_BUFFERING`` require the buffer length
    (and the file offset) to be a multiple of the logical sector size
    (typically 4 096 bytes).  If *data* already satisfies this constraint it
    is returned unchanged to avoid an unnecessary copy.

    The zero padding written beyond ``file_size`` is harmless: a dedicated
    slack-space pass later overwrites that region with random data.

    Args:
        data: Raw bytes to be written.

    Returns:
        *data* padded to the next sector boundary.
    """
    remainder = len(data) % _SECTOR_SIZE
    if remainder == 0:
        return data
    return data + b"\x00" * (_SECTOR_SIZE - remainder)


# ══════════════════════════════════════════════════════════════════════════════
# 3a. Slack Space
# ══════════════════════════════════════════════════════════════════════════════


async def _wipe_slack_space(ctx: _DirectIOContext, file_size: int) -> None:
    """Overwrite the slack space between EOF and the cluster boundary.

    Most filesystems allocate storage in fixed-size clusters (typically
    4 096 bytes).  When a file does not fill its last cluster, the remaining
    bytes — the *slack space* — may contain residual data from a previously
    deleted file.  This function overwrites those bytes with cryptographic
    random data.

    If ``file_size`` is already an exact multiple of :data:`_CLUSTER_SIZE`
    there is no slack space and the function returns immediately.

    Writes beyond EOF may be silently rejected by some filesystems (NTFS
    compressed files, FAT); any ``OSError`` is caught and ignored.

    Args:
        ctx: Open :class:`_DirectIOContext` for the file being wiped.
        file_size: Logical size of the file in bytes.
    """
    padded = _aligned_size(file_size, _CLUSTER_SIZE)
    slack = padded - file_size
    if slack <= 0:
        return

    try:
        await ctx.seek(file_size)
        data = await asyncio.to_thread(os.urandom, slack)
        aligned = _make_aligned_buffer(data)
        await ctx.write(aligned[: _aligned_size(slack)])
        await ctx.flush()
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 3b. Alternate Data Streams (Windows only)
# ══════════════════════════════════════════════════════════════════════════════


def _enumerate_ads_windows(path: Path) -> list[str]:
    """Return the names of all Alternate Data Streams attached to *path*.

    Uses the ``FindFirstStreamW`` / ``FindNextStreamW`` Win32 API (available
    since Windows Vista) to enumerate streams without any external dependency.
    The default data stream ``::$DATA`` is excluded from the result.

    Returns an empty list on non-Windows platforms or when the API is
    unavailable (e.g. on ReFS with streams disabled).

    Args:
        path: File whose ADS should be enumerated.

    Returns:
        A list of stream name strings such as ``[":thumbnail:$DATA"]``.
    """
    if sys.platform != "win32":
        return []

    BUF_CHARS = 296
    # WIN32_FIND_STREAM_DATA layout:
    #   LARGE_INTEGER StreamSize  (8 bytes)
    #   WCHAR cStreamName[296]    (592 bytes)

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", ctypes.c_int64),
            ("cStreamName", ctypes.c_wchar * BUF_CHARS),
        ]

    k32 = ctypes.windll.kernel32
    find_first = getattr(k32, "FindFirstStreamW", None)
    find_next = getattr(k32, "FindNextStreamW", None)
    find_close = getattr(k32, "FindClose", None)

    if not all((find_first, find_next, find_close)):
        return []

    data = WIN32_FIND_STREAM_DATA()
    handle = find_first(str(path), 0, ctypes.byref(data), 0)

    INVALID = ctypes.c_void_p(-1).value
    if handle == INVALID or handle is None:
        return []

    ads_names: list[str] = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                ads_names.append(name)
            if not find_next(handle, ctypes.byref(data)):
                break
    finally:
        find_close(handle)

    return ads_names


async def _wipe_ads_windows(path: Path, buffer_size: int) -> None:
    """Overwrite and delete every Alternate Data Stream of *path*.

    ADS are enumerated before touching the main stream because
    ``FindFirstStreamW`` requires the file to still exist.  Each stream is
    overwritten with random bytes, fsynced, and then removed.

    This is a no-op on non-Windows platforms.

    Args:
        path: File whose ADS should be wiped.
        buffer_size: Maximum chunk size for random-data writes.
    """
    if sys.platform != "win32":
        return

    ads_list = await asyncio.to_thread(_enumerate_ads_windows, path)
    for stream_name in ads_list:
        ads_path_str = f"{path}{stream_name}"
        try:
            ads_size = os.path.getsize(ads_path_str)
        except OSError:
            continue

        if ads_size <= 0:
            try:
                os.remove(ads_path_str)
            except OSError:
                pass
            continue

        try:
            async with aiofiles.open(ads_path_str, "rb+") as ads_f:
                remaining = ads_size
                while remaining > 0:
                    chunk = min(remaining, buffer_size)
                    data = await asyncio.to_thread(os.urandom, chunk)
                    await ads_f.write(data)
                    remaining -= chunk
                await ads_f.flush()
                await asyncio.to_thread(os.fsync, ads_f.fileno())
        except OSError:
            pass

        try:
            os.remove(ads_path_str)
        except OSError:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# Main engine
# ══════════════════════════════════════════════════════════════════════════════

ProgressCallbackType = Optional[
    Callable[
        [Path, int, int, int],
        Coroutine[Any, Any, None] | None,
    ]
]


class AsyncWiper:
    """Asynchronous secure-erase engine.

    Combines Direct I/O, multi-pass overwriting, slack-space wiping, ADS
    destruction (Windows), inode-metadata scrubbing, and TRIM dispatch
    into a single ``await``-able call.

    Args:
        audit_logger: Optional :class:`~audit.AuditLogger` instance.
            Defaults to a new logger writing to ``madara_audit.jsonl`` in the
            current working directory.
    """

    def __init__(self, audit_logger: Optional[AuditLogger] = None) -> None:
        self.audit = audit_logger or AuditLogger()
        self.BUFFER_HDD = 10 * 1024 * 1024  # 10 MB
        self.BUFFER_SSD = 50 * 1024 * 1024  # 50 MB

    async def wipe_file(
        self,
        path: Path,
        standard: SanitizationStandard = SanitizationStandard.NIST_CLEAR,
        verify: bool = False,
        progress_callback: ProgressCallbackType = None,
    ) -> dict[str, Any]:
        """Securely erase a single file.

        Execution order:

        1. ADS enumeration and wiping (Windows only).
        2. Open the file with Direct I/O (falls back if unsupported).
        3. Overwrite with the pass sequence dictated by *standard* and
           the detected storage type.
        4. Overwrite the slack space between EOF and the cluster boundary.
        5. Optionally verify by sampling Shannon entropy.
        6. Destroy inode metadata (timestamps + multi-rename).
        7. Delete the file.
        8. Send TRIM to the storage controller (SSD/NVMe only).
        9. Write an audit-log record.

        The :class:`_DirectIOContext` is always closed in a ``finally``
        block, even when an ``OSError`` occurs mid-pass.

        Args:
            path: Absolute path to the file to wipe.
            standard: Sanitization standard that controls the number of
                passes for HDDs.
            verify: When ``True``, read random blocks after wiping and
                verify Shannon entropy (≥ 7.0 bits/byte for random passes,
                ≤ 0.1 for deterministic passes).
            progress_callback: Optional async or sync callable with
                signature ``(path, pass_index, bytes_written, file_size)``.

        Returns:
            A dictionary with the following keys:

            * ``success`` (bool)
            * ``passes_completed`` (int)
            * ``verified`` (bool | None)
            * ``duration`` (float) — seconds
            * ``strategy`` (str)
            * ``error`` (str | None)
            * ``trim_sent`` (bool)
            * ``direct_io`` (bool)
            * ``ads_wiped`` (int)
            * ``slack_wiped`` (bool)
        """
        result: dict[str, Any] = {
            "success": False,
            "passes_completed": 0,
            "verified": False,
            "duration": 0.0,
            "strategy": "Unknown",
            "error": None,
            "trim_sent": False,
            "direct_io": False,
            "ads_wiped": 0,
            "slack_wiped": False,
        }

        sha256_before = "unknown"
        file_size_for_audit = 0
        current_path = path

        try:
            if not path.exists():
                raise FileNotFoundError(f"No se encuentra el archivo: {path}")

            file_size_for_audit = path.stat().st_size
            _ensure_writable(path)
            storage_type = detect_storage_type(path)

            if storage_type in (StorageType.SSD, StorageType.NVME):
                strategy_name = "SSD/NVMe"
                buffer_size = self.BUFFER_SSD
            else:
                strategy_name = "HDD"
                buffer_size = self.BUFFER_HDD

            result["strategy"] = f"{strategy_name} ({standard.value})"

            sha256_before = await self._calculate_sha256(path)
            passes_config = self._get_passes_config(storage_type, standard)
            passes_done = 0
            start_time = time.time()

            # ── 3b. ADS: enumerate and destroy before touching the main
            #         stream, while FindFirstStreamW can still find them.
            if sys.platform == "win32":
                ads_before = await asyncio.to_thread(_enumerate_ads_windows, path)
                await _wipe_ads_windows(path, buffer_size)
                result["ads_wiped"] = len(ads_before)

            # ── 2. Open with Direct I/O ───────────────────────────────────
            ctx = await _open_direct(path)
            result["direct_io"] = ctx.direct

            try:
                for pass_idx, pattern_type in enumerate(passes_config, 1):
                    await ctx.seek(0)
                    remaining = file_size_for_audit
                    bytes_this_pass = 0

                    while remaining > 0:
                        raw_chunk = min(remaining, buffer_size)
                        data = await self._generate_pattern(pattern_type, raw_chunk)

                        if ctx.direct:
                            data = _make_aligned_buffer(data)

                        written = await ctx.write(data)
                        logical = min(raw_chunk, written) if written else raw_chunk
                        remaining -= logical
                        bytes_this_pass += logical

                        if progress_callback:
                            if asyncio.iscoroutinefunction(progress_callback):
                                await progress_callback(
                                    path, pass_idx, bytes_this_pass, file_size_for_audit
                                )
                            else:
                                progress_callback(
                                    path, pass_idx, bytes_this_pass, file_size_for_audit
                                )

                    await ctx.flush()
                    passes_done += 1

                # ── 3a. Slack Space ───────────────────────────────────────
                await _wipe_slack_space(ctx, file_size_for_audit)
                result["slack_wiped"] = True

            finally:
                # Always close the descriptor, even on mid-pass I/O errors.
                await ctx.close()

            result["duration"] = time.time() - start_time
            result["passes_completed"] = passes_done
            result["success"] = True

            if verify:
                verified = await self._verify_entropy(
                    path, expected_pattern=passes_config[-1]
                )
                result["verified"] = verified
                if not verified:
                    result["error"] = "Verificación de entropía fallida"
                    result["success"] = False
            else:
                result["verified"] = None

            # ── 1. Metadata destruction + unlink ─────────────────────────
            try:
                current_path = await asyncio.to_thread(_destroy_metadata, path)
                current_path.unlink()
            except Exception as exc:
                result["error"] = (
                    f"Borrado completado pero fallo al eliminar inodo: {exc}"
                )

            # ── TRIM (SSD/NVMe only) ──────────────────────────────────────
            if result["success"] and storage_type in (StorageType.SSD, StorageType.NVME):
                trim_ok = await asyncio.to_thread(send_trim, path)
                result["trim_sent"] = trim_ok

        except Exception as exc:
            result["error"] = str(exc)
            result["success"] = False

        self.audit.log_wipe_operation(
            path,
            file_size_for_audit,
            sha256_before,
            standard.value,
            result,
        )

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _get_passes_config(
        self,
        storage_type: StorageType,
        standard: SanitizationStandard,
    ) -> list[str]:
        """Return the ordered list of pass patterns for the given parameters.

        Args:
            storage_type: Detected storage technology.
            standard: Requested sanitization level.

        Returns:
            A list of pattern identifiers: ``"zeros"``, ``"ones"``,
            ``"random"``.
        """
        if storage_type in (StorageType.SSD, StorageType.NVME):
            return ["random"]
        if standard == SanitizationStandard.NIST_CLEAR:
            return ["zeros"]
        return ["zeros", "ones", "random"]

    async def _generate_pattern(self, pattern_type: str, size: int) -> bytes:
        """Generate a buffer of *size* bytes for an overwrite pass.

        Args:
            pattern_type: One of ``"zeros"``, ``"ones"``, or ``"random"``.
            size: Number of bytes to generate.

        Returns:
            The pattern buffer.
        """
        if pattern_type == "zeros":
            return b"\x00" * size
        if pattern_type == "ones":
            return b"\xFF" * size
        return await asyncio.to_thread(os.urandom, size)

    async def _calculate_sha256(self, path: Path) -> str:
        """Compute the SHA-256 digest of *path* before wiping.

        Streamed in 1 MB chunks to keep memory usage bounded.

        Args:
            path: File to hash.

        Returns:
            Hex-encoded SHA-256 digest, or ``"hash_error"`` on failure.
        """
        sha256 = hashlib.sha256()
        try:
            async with aiofiles.open(path, "rb") as f:
                while chunk := await f.read(1024 * 1024):
                    sha256.update(chunk)
        except Exception:
            return "hash_error"
        return sha256.hexdigest()

    async def _verify_entropy(
        self,
        path: Path,
        expected_pattern: str = "random",
        sample_count: int = 20,
        block_size: int = 4096,
    ) -> bool:
        """Verify that the file's contents match the expected entropy profile.

        Samples *sample_count* random 4 KB blocks and computes the average
        Shannon entropy.  A value above 7.0 bits/byte indicates a random
        distribution (expected after a random-overwrite pass); below 0.1
        indicates a uniform pattern (zeros or ones).

        Args:
            path: File to verify.
            expected_pattern: ``"random"`` or any deterministic pattern
                string.
            sample_count: Number of blocks to sample.
            block_size: Size of each sampled block in bytes.

        Returns:
            ``True`` if the entropy matches the expectation, ``False``
            otherwise.
        """
        if not path.exists() or path.stat().st_size == 0:
            return True

        file_size = path.stat().st_size

        def calc_entropy(data: bytes) -> float:
            if not data:
                return 0.0
            counter = Counter(data)
            length = len(data)
            return -sum(
                (c / length) * math.log2(c / length) for c in counter.values()
            )

        total_entropy = 0.0
        samples_taken = 0

        try:
            async with aiofiles.open(path, "rb") as f:
                for _ in range(sample_count):
                    offset = (
                        random.randint(0, max(0, file_size - block_size))
                        if file_size > block_size
                        else 0
                    )
                    await f.seek(offset)
                    data = await f.read(block_size)
                    if data:
                        total_entropy += calc_entropy(data)
                        samples_taken += 1
        except Exception:
            return False

        if samples_taken == 0:
            return True

        avg_entropy = total_entropy / samples_taken
        return avg_entropy > 7.0 if expected_pattern == "random" else avg_entropy < 0.1
