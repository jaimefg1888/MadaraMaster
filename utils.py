#!/usr/bin/env python3
"""
MadaraMaster — Utility Functions
=================================
Shared helper functions for formatting and display.

Author : MadaraMaster Team
License: MIT — Authorized Data Sanitization Use Only
"""


def format_bytes(size: int) -> str:
    """
    Converts a byte count into a smart, human-readable string.

    Rules:
        < 1 KB  → "512 B"       (no decimals — they're meaningless at this scale)
        < 1 MB  → "12.5 KB"     (1 decimal)
        < 1 GB  → "45.8 MB"     (1 decimal)
        ≥ 1 GB  → "1.23 GB"     (2 decimals for precision at large scale)
        ≥ 1 TB  → "2.50 TB"     (2 decimals)

    Fixes the v2.2 bug where small values displayed as "0.00 B".
    """
    if size < 0:
        return "0 B"

    if size < 1024:
        return f"{size} B"

    units = [
        (1024 ** 4, "TB", 2),
        (1024 ** 3, "GB", 2),
        (1024 ** 2, "MB", 1),
        (1024 ** 1, "KB", 1),
    ]

    for threshold, unit, decimals in units:
        if size >= threshold:
            value = size / threshold
            return f"{value:.{decimals}f} {unit}"

    return f"{size} B"
