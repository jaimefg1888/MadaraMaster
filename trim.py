#!/usr/bin/env python3
# Módulo TRIM — hook post-borrado para forzar el GC del controlador SSD/NVMe
# jaimefg1888
#
# Linux  → ioctl FITRIM sobre el directorio padre (sin subprocess).
#           Requiere CAP_SYS_ADMIN; falla silenciosamente si no hay permisos.
#
# Windows → DeviceIoControl con IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES
#           (DataSetManagementAction_Trim).
#           Requiere acceso de administrador; falla silenciosamente si no.
#
# macOS   → no-op.  El sistema de archivos APFS gestiona el TRIM de forma
#           transparente; no hay API pública sin IOKit/PyObjC.

from __future__ import annotations

import ctypes
import logging
import os
import platform
import struct
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def send_trim(path: Path) -> bool:
    """Send a TRIM/Discard command to the storage controller for *path*.

    Dispatches to the platform-specific implementation.  Never raises:
    any error is logged at DEBUG level and ``False`` is returned so callers
    can treat TRIM as a best-effort optimisation rather than a hard
    requirement.

    Args:
        path: A path on the filesystem whose free space should be trimmed.
            Typically the parent directory of the file that was just deleted.

    Returns:
        ``True`` if the TRIM command was issued successfully, ``False``
        otherwise.
    """
    system = platform.system().lower()
    try:
        if system == "linux":
            return _trim_linux(path)
        if system == "windows":
            return _trim_windows(path)
    except Exception as exc:
        log.debug("TRIM: excepción ignorada en %s: %s", system, exc)
    return False


# ════════════════════════════════════════════════════════════════
# LINUX — ioctl FITRIM
# ════════════════════════════════════════════════════════════════
#
# FITRIM = _IOWR('X', 121, struct fstrim_range)
#
# struct fstrim_range { __u64 start; __u64 len; __u64 minlen; }  → 24 bytes
#
# The macro expands to:
#   ((_IOC_READ | _IOC_WRITE) << 30) | ('X' << 8) | 121 | (24 << 16)
#   = (3 << 30) | (0x58 << 8) | 0x79 | (24 << 16)
#   = 0xC0185879
#
# We open the *parent directory* with O_RDONLY | O_DIRECTORY because
# FITRIM operates on a mounted filesystem, not on an individual file.
# Submitting the ioctl against the directory fd instructs the kernel to
# issue DISCARD commands for all free extents on that volume.
# ════════════════════════════════════════════════════════════════

_FITRIM: int = (
    (3 << 30)  # _IOC_READ | _IOC_WRITE
    | (0x58 << 8)  # ord('X')
    | 121  # nr
    | (struct.calcsize("QQQ") << 16)  # sizeof(struct fstrim_range) = 24
)
# struct fstrim_range: start=0, len=UINT64_MAX, minlen=0 (trim everything)
_FSTRIM_RANGE: bytes = struct.pack("QQQ", 0, (1 << 64) - 1, 0)


def _trim_linux(path: Path) -> bool:
    """Issue a ``FITRIM`` ioctl on the filesystem that contains *path*.

    Opens the parent directory with ``O_RDONLY | O_DIRECTORY`` and calls
    ``fcntl.ioctl(FITRIM, ...)`` to ask the kernel to emit ``DISCARD``
    (trim) commands for all free blocks on the underlying block device.

    ``CAP_SYS_ADMIN`` is required.  On consumer systems without that
    capability, the call returns ``EPERM``; the function logs a debug
    message and returns ``False`` rather than raising.

    As an alternative to running as root, the filesystem can be mounted
    with the ``discard`` option (continuous TRIM) or the system-wide
    ``fstrim.timer`` systemd unit can be used.

    Args:
        path: Any path on the target filesystem.

    Returns:
        ``True`` on success, ``False`` on any error.
    """
    if sys.platform == "win32":
        return False

    try:
        import fcntl
    except ImportError:
        return False

    parent = path.parent if path.is_file() else path
    if not parent.exists():
        parent = path.parent

    try:
        fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        log.debug("TRIM Linux: no se pudo abrir %s: %s", parent, exc)
        return False

    try:
        buf = bytearray(_FSTRIM_RANGE)
        fcntl.ioctl(fd, _FITRIM, buf)
        trimmed = struct.unpack("QQQ", buf)[1]
        log.debug("TRIM Linux: %.1f MB liberados en %s", trimmed / 1024 / 1024, parent)
        return True
    except PermissionError:
        log.debug(
            "TRIM Linux: FITRIM denegado en %s — se requiere CAP_SYS_ADMIN.  "
            "Considera montar con 'discard' o ejecutar como root.",
            parent,
        )
        return False
    except OSError as exc:
        log.debug("TRIM Linux: FITRIM falló en %s: %s", parent, exc)
        return False
    finally:
        os.close(fd)


# ════════════════════════════════════════════════════════════════
# WINDOWS — DeviceIoControl con DataSetManagementAction_Trim
# ════════════════════════════════════════════════════════════════
#
# IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES
#   = CTL_CODE(IOCTL_STORAGE_BASE=0x2d, 0x501, METHOD_BUFFERED=0,
#              FILE_WRITE_ACCESS=2)
#   = (0x2d << 16) | (2 << 14) | (0x501 << 2) | 0
#   = 0x002D9404
#
# Unlike FITRIM on Linux, this IOCTL requires GENERIC_WRITE access to the
# volume handle, which means administrator privileges are required.
# ════════════════════════════════════════════════════════════════

_IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES: int = 0x002D9404
_DataSetManagementAction_Trim: int = 0x00000001

_FILE_SHARE_READ: int = 0x00000001
_FILE_SHARE_WRITE: int = 0x00000002
_OPEN_EXISTING: int = 3
_GENERIC_WRITE: int = 0x40000000
_INVALID_HANDLE_VALUE: int = ctypes.c_void_p(-1).value

# DEVICE_MANAGE_DATA_SET_ATTRIBUTES (7 × DWORD = 28 bytes)
_DMDSA_FMT: str = "IIIIIII"
_DMDSA_SIZE: int = struct.calcsize(_DMDSA_FMT)  # 28
# DEVICE_DATA_SET_RANGE (1 × LONGLONG + 1 × ULONGLONG = 16 bytes)
_RANGE_FMT: str = "qQ"
_RANGE_SIZE: int = struct.calcsize(_RANGE_FMT)  # 16


def _trim_windows(path: Path) -> bool:
    """Emit ``DataSetManagementAction_Trim`` for the volume that contains *path*.

    Builds a ``DEVICE_MANAGE_DATA_SET_ATTRIBUTES`` structure with a
    ``DEVICE_DATA_SET_RANGE`` covering the entire volume (offset=0,
    length=0 signals "the whole device" to the driver) and sends it via
    ``DeviceIoControl``.

    Administrator privileges are required because ``GENERIC_WRITE`` access
    to the volume handle is needed.

    Args:
        path: Any path on the target volume.

    Returns:
        ``True`` if the IOCTL was accepted by the driver, ``False``
        otherwise.
    """
    if sys.platform != "win32":
        return False

    try:
        import ctypes.wintypes  # noqa: F401
    except ImportError:
        return False

    handle = _open_volume_write_handle_windows(path)
    if handle is None or handle == _INVALID_HANDLE_VALUE:
        log.debug("TRIM Windows: no se pudo abrir el volumen de %s", path)
        return False

    try:
        return _issue_trim_ioctl(handle)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _open_volume_write_handle_windows(path: Path) -> Optional[int]:
    """Open a GENERIC_WRITE handle to the logical volume containing *path*.

    Args:
        path: Any path on the target volume.

    Returns:
        A valid Win32 ``HANDLE`` cast to ``int``, or ``None`` on failure.
    """
    try:
        k32 = ctypes.windll.kernel32
        vol_buf = ctypes.create_unicode_buffer(260)
        if not k32.GetVolumePathNameW(str(path), vol_buf, 260):
            return None
        drive = vol_buf.value.rstrip("\\")
        unc = f"\\\\.\\{drive}"
        handle = k32.CreateFileW(
            unc,
            _GENERIC_WRITE,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
        return None if handle == _INVALID_HANDLE_VALUE else handle
    except Exception:
        return None


def _issue_trim_ioctl(handle: int) -> bool:
    """Build the DMDSA payload and dispatch ``IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES``.

    Args:
        handle: An open Win32 handle with GENERIC_WRITE access to the volume.

    Returns:
        ``True`` if ``DeviceIoControl`` succeeded, ``False`` otherwise.
    """
    payload: bytes = struct.pack(
        _DMDSA_FMT,
        _DMDSA_SIZE,                  # Size
        _DataSetManagementAction_Trim, # Action
        0,                            # Flags
        0,                            # ParameterBlockOffset
        0,                            # ParameterBlockLength
        _DMDSA_SIZE,                  # DataSetRangesOffset (immediately after header)
        _RANGE_SIZE,                  # DataSetRangesLength
    ) + struct.pack(_RANGE_FMT, 0, 0) # Range: offset=0, length=0 (entire volume)

    buf = ctypes.create_string_buffer(payload)
    bytes_ret = ctypes.c_ulong(0)

    ok: bool = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        _IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES,
        buf,
        len(payload),
        None,
        0,
        ctypes.byref(bytes_ret),
        None,
    )
    if ok:
        log.debug("TRIM Windows: IOCTL TRIM enviado correctamente.")
        return True

    err: int = ctypes.windll.kernel32.GetLastError()
    log.debug("TRIM Windows: DeviceIoControl falló, GetLastError=%d", err)
    return False
