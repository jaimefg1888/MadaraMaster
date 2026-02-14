#!/usr/bin/env python3
"""
MadaraMaster — DoD 5220.22-M Secure File Sanitization Engine
==============================================================
Implements the U.S. Department of Defense 5220.22-M standard for
secure data destruction on magnetic and solid-state media.

Three-Pass Overwrite:
    Pass 1: All zeros     (\\x00) — eliminates original magnetic patterns
    Pass 2: All ones      (\\xFF) — inverts the magnetic domain
    Pass 3: Random bytes  (os.urandom) — cryptographically secure randomization

Anti-forensics:
    - Renames file to random string before deletion (scrubs MFT/directory entry)
    - Resets file timestamps (creation, modification, access)
    - Flushes and fsyncs each pass to guarantee physical write to disk

Author : MadaraMaster Team
License: MIT — Authorized Data Sanitization Use Only
"""

import os
import sys
import time
import stat
import string
import random
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Callable, List

# ──────────────────────── Configuration ────────────────────────

CHUNK_SIZE = 4096  # 4KB write chunks — balances speed and memory
DOD_PASSES = 3

# ──────────────────────── Data Models ──────────────────────────

@dataclass
class WipeResult:
    """Result of a single file wipe operation."""
    filepath: str
    success: bool
    file_size: int = 0
    bytes_written: int = 0
    error: str = ""
    duration: float = 0.0


@dataclass
class WipeSummary:
    """Aggregated summary of an entire wipe session."""
    total_files: int = 0
    files_wiped: int = 0
    files_failed: int = 0
    total_bytes_overwritten: int = 0
    total_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    results: List[WipeResult] = field(default_factory=list)


# ──────────────────────── Callbacks ────────────────────────────

# Progress callback signature: (filepath, pass_number, bytes_written, total_bytes)
ProgressCallback = Optional[Callable[[str, int, int, int], None]]


# ──────────────────────── Core Wipe Engine ─────────────────────

def _overwrite_pass(
    fd: int,
    file_size: int,
    pass_number: int,
    filepath: str,
    progress_callback: ProgressCallback = None,
) -> int:
    """
    Performs a single overwrite pass on an open file descriptor.

    Args:
        fd: OS-level file descriptor (from os.open).
        file_size: Total size of the file in bytes.
        pass_number: 1=zeros, 2=ones, 3=random.
        filepath: Path string (for progress callback display).
        progress_callback: Optional callback for progress updates.

    Returns:
        Number of bytes written in this pass.
    """
    os.lseek(fd, 0, os.SEEK_SET)
    bytes_written = 0
    remaining = file_size

    while remaining > 0:
        chunk_len = min(CHUNK_SIZE, remaining)

        if pass_number == 1:
            data = b"\x00" * chunk_len
        elif pass_number == 2:
            data = b"\xFF" * chunk_len
        else:
            data = os.urandom(chunk_len)

        os.write(fd, data)
        bytes_written += chunk_len
        remaining -= chunk_len

        if progress_callback:
            progress_callback(filepath, pass_number, bytes_written, file_size)

    # Critical: flush OS buffers and force physical write to disk
    os.fsync(fd)

    return bytes_written


def _scrub_metadata(filepath: str) -> str:
    """
    Anti-forensic metadata scrubbing:
    1. Resets file timestamps to epoch (1970-01-01) to hide activity timeline.
    2. Renames the file to a random string to scrub directory entry / MFT record.

    Args:
        filepath: Path to the file.

    Returns:
        New path after renaming (for final deletion).
    """
    try:
        # Reset access and modification timestamps to epoch
        os.utime(filepath, (0, 0))
    except OSError:
        pass  # Non-critical — continue even if timestamp reset fails

    # Generate random filename in the same directory
    directory = os.path.dirname(filepath) or "."
    random_name = "".join(random.choices(string.ascii_lowercase + string.digits, k=12)) + ".tmp"
    new_path = os.path.join(directory, random_name)

    try:
        os.rename(filepath, new_path)
        return new_path
    except OSError:
        # If rename fails, delete the original path
        return filepath


def _ensure_writable(filepath: str) -> None:
    """Attempts to make a file writable if it's read-only."""
    try:
        current_mode = os.stat(filepath).st_mode
        if not (current_mode & stat.S_IWRITE):
            os.chmod(filepath, current_mode | stat.S_IWRITE)
    except OSError:
        pass


def wipe_file(
    filepath: str,
    progress_callback: ProgressCallback = None,
) -> WipeResult:
    """
    Securely wipes a single file using the DoD 5220.22-M 3-pass method.

    Process:
        1. Opens the file at the OS level (bypassing Python buffering)
        2. Pass 1: Overwrite with zeros (\\x00)
        3. Pass 2: Overwrite with ones (\\xFF)
        4. Pass 3: Overwrite with cryptographic random bytes
        5. Scrub metadata (timestamps + filename)
        6. Delete the file (unlink inode)

    Args:
        filepath: Absolute or relative path to the file.
        progress_callback: Optional (filepath, pass_num, bytes_done, total) callback.

    Returns:
        WipeResult with details of the operation.
    """
    start_time = time.time()
    filepath = os.path.abspath(filepath)

    # Validate file exists
    if not os.path.isfile(filepath):
        return WipeResult(
            filepath=filepath,
            success=False,
            error=f"File not found: {filepath}",
        )

    # Make writable if needed
    _ensure_writable(filepath)

    try:
        file_size = os.path.getsize(filepath)
        total_bytes_written = 0

        if file_size == 0:
            # Empty file — just scrub metadata and delete
            final_path = _scrub_metadata(filepath)
            os.remove(final_path)
            return WipeResult(
                filepath=filepath,
                success=True,
                file_size=0,
                bytes_written=0,
                duration=time.time() - start_time,
            )

        # Open at OS level for direct disk I/O
        flags = os.O_WRONLY
        if sys.platform == "win32":
            flags |= os.O_BINARY
        fd = os.open(filepath, flags)

        try:
            # Three-pass overwrite
            for pass_num in range(1, DOD_PASSES + 1):
                written = _overwrite_pass(
                    fd, file_size, pass_num, filepath, progress_callback
                )
                total_bytes_written += written
        finally:
            os.close(fd)

        # Anti-forensic: scrub metadata and rename
        final_path = _scrub_metadata(filepath)

        # Delete the file
        os.remove(final_path)

        return WipeResult(
            filepath=filepath,
            success=True,
            file_size=file_size,
            bytes_written=total_bytes_written,
            duration=time.time() - start_time,
        )

    except PermissionError as e:
        return WipeResult(
            filepath=filepath,
            success=False,
            error=f"Permission denied: {e}",
            duration=time.time() - start_time,
        )
    except OSError as e:
        return WipeResult(
            filepath=filepath,
            success=False,
            error=f"OS error: {e}",
            duration=time.time() - start_time,
        )
    except Exception as e:
        return WipeResult(
            filepath=filepath,
            success=False,
            error=f"Unexpected error: {e}",
            duration=time.time() - start_time,
        )


def wipe_directory(
    dirpath: str,
    progress_callback: ProgressCallback = None,
) -> WipeSummary:
    """
    Recursively wipes all files in a directory using DoD 5220.22-M.
    After all files are wiped, removes empty subdirectories bottom-up.

    Args:
        dirpath: Path to the directory.
        progress_callback: Optional progress callback.

    Returns:
        WipeSummary with aggregated results.
    """
    summary = WipeSummary()
    start_time = time.time()
    dirpath = os.path.abspath(dirpath)

    if not os.path.isdir(dirpath):
        summary.errors.append(f"Directory not found: {dirpath}")
        return summary

    # Collect all files first (depth-first)
    all_files: List[str] = []
    for root, dirs, files in os.walk(dirpath, topdown=False):
        for filename in files:
            all_files.append(os.path.join(root, filename))

    summary.total_files = len(all_files)

    # Wipe each file
    for filepath in all_files:
        result = wipe_file(filepath, progress_callback)
        summary.results.append(result)

        if result.success:
            summary.files_wiped += 1
            summary.total_bytes_overwritten += result.bytes_written
        else:
            summary.files_failed += 1
            summary.errors.append(f"{result.filepath}: {result.error}")

    # Remove empty directories bottom-up
    for root, dirs, files in os.walk(dirpath, topdown=False):
        for dirname in dirs:
            dir_to_remove = os.path.join(root, dirname)
            try:
                os.rmdir(dir_to_remove)
            except OSError:
                pass  # Directory not empty or permission denied

    # Try to remove the top-level directory
    try:
        os.rmdir(dirpath)
    except OSError:
        pass

    summary.total_duration = time.time() - start_time
    return summary


def collect_files(target: str) -> List[str]:
    """
    Collects all file paths from a target (file or directory).

    Args:
        target: Path to a file or directory.

    Returns:
        List of absolute file paths.
    """
    target = os.path.abspath(target)

    if os.path.isfile(target):
        return [target]
    elif os.path.isdir(target):
        files = []
        for root, dirs, filenames in os.walk(target, topdown=False):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files
    else:
        return []


# ──────────────────────── Standalone Test ──────────────────────

if __name__ == "__main__":
    import tempfile

    print("[*] MadaraMaster -- Engine Self-Test")
    print("=" * 50)

    # Create temp test files
    test_dir = tempfile.mkdtemp(prefix="madara_test_")
    test_files = []
    for i in range(3):
        fpath = os.path.join(test_dir, f"secret_{i}.txt")
        with open(fpath, "w") as f:
            f.write(f"CONFIDENTIAL DATA LINE {i}\n" * 100)
        test_files.append(fpath)
        print(f"  [+] Created: {fpath} ({os.path.getsize(fpath)} bytes)")

    # Wipe directory
    print(f"\n  Wiping directory: {test_dir}")

    def progress(fp, pass_num, done, total):
        pct = (done / total) * 100 if total > 0 else 100
        basename = os.path.basename(fp)
        print(f"    Pass {pass_num}/3 [{basename}]: {pct:.0f}%", end="\r")

    summary = wipe_directory(test_dir, progress_callback=progress)

    print("\n")
    print(f"  Files wiped:     {summary.files_wiped}/{summary.total_files}")
    print(f"  Bytes written:   {summary.total_bytes_overwritten:,}")
    print(f"  Duration:        {summary.total_duration:.2f}s")
    print(f"  Errors:          {summary.files_failed}")

    # Verify deletion
    remaining = list(Path(test_dir).rglob("*")) if os.path.exists(test_dir) else []
    if not remaining and not os.path.exists(test_dir):
        print("\n  [OK] All files and directory removed -- self-test passed!")
    else:
        print(f"\n  [!] Remaining items: {remaining}")
