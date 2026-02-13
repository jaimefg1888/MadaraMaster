#!/usr/bin/env python3
"""
Neutron-Wipe — CLI Interface
==============================
Professional cyberpunk-themed CLI for secure file sanitization.
Implements DoD 5220.22-M with real-time progress visualization.

Usage:
    python main.py wipe <TARGET>              # Wipe a file or directory
    python main.py wipe <TARGET> --confirm    # Skip confirmation prompt
    python main.py wipe <TARGET> --dry-run    # Preview without deleting

Author : Neutron Security Team
License: MIT — Authorized Data Sanitization Use Only
"""

import os
import sys
import time
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TaskProgressColumn,
    MofNCompleteColumn,
)
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box

from wiper import (
    wipe_file,
    wipe_directory,
    collect_files,
    WipeResult,
    WipeSummary,
    DOD_PASSES,
)

# ──────────────────────── App Setup ────────────────────────────

app = typer.Typer(
    name="neutron-wipe",
    help="🧹 Neutron-Wipe — DoD 5220.22-M Secure File Sanitization",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

VERSION = "1.0.0"

BANNER = """
 ███╗   ███╗ █████╗ ██████╗  █████╗ ██████╗  █████╗ 
 ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
 ██╔████╔██║███████║██║  ██║███████║██████╔╝███████║
 ██║╚██╔╝██║██╔══██║██║  ██║██╔══██║██╔══██╗██╔══██║
 ██║ ╚═╝ ██║██║  ██║██████╔╝██║  ██║██║  ██║██║  ██║
 ╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
      ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ 
      ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
      ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝
      ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗
      ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║
      ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ 
                                                           
   MadaraMaster v1.0 • Created by jaimefg1888 • DoD 5220.22-M
"""
PASS_LABELS = {
    1: ("Pass 1/3 · Zeros", "bright_red"),
    2: ("Pass 2/3 · Ones", "bright_yellow"),
    3: ("Pass 3/3 · Random", "bright_green"),
}


# ──────────────────────── UI Helpers ───────────────────────────

def print_banner():
    """Displays the cyberpunk banner."""
    console.print(
        Panel(
            Align.center(Text(BANNER, style="bold red")),
            border_style="bright_cyan",
            box=box.DOUBLE_EDGE,
            subtitle=f"[dim]DoD 5220.22-M Compliant · v{VERSION}[/]",
        )
    )


def format_bytes(b: int) -> str:
    """Formats bytes into human-readable units."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024.0:
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} PB"


def print_summary(summary: WipeSummary):
    """Displays the post-wipe summary table."""
    table = Table(
        title="[bold bright_cyan]🧹 WIPE SUMMARY[/]",
        box=box.DOUBLE_EDGE,
        border_style="bright_cyan",
        padding=(0, 2),
        show_lines=True,
    )
    table.add_column("Metric", style="bold white", min_width=25)
    table.add_column("Value", style="bold", min_width=20, justify="right")

    # Files
    success_style = "bright_green" if summary.files_wiped > 0 else "dim"
    fail_style = "bright_red" if summary.files_failed > 0 else "bright_green"

    table.add_row("Total Files Targeted", f"[cyan]{summary.total_files}[/]")
    table.add_row("Files Wiped Successfully", f"[{success_style}]{summary.files_wiped}[/]")
    table.add_row("Files Failed", f"[{fail_style}]{summary.files_failed}[/]")
    table.add_row("─" * 25, "─" * 20)

    # Bytes
    total_overwritten = summary.total_bytes_overwritten
    table.add_row(
        "Total Bytes Overwritten",
        f"[bright_yellow]{total_overwritten:,}[/] [dim]({format_bytes(total_overwritten)})[/]"
    )
    table.add_row(
        "Effective Data Written (3 passes)",
        f"[bright_yellow]{format_bytes(total_overwritten)}[/]"
    )
    table.add_row("─" * 25, "─" * 20)

    # Time
    table.add_row("Total Duration", f"[bright_magenta]{summary.total_duration:.3f}s[/]")

    if total_overwritten > 0 and summary.total_duration > 0:
        speed = total_overwritten / summary.total_duration
        table.add_row("Average Write Speed", f"[dim]{format_bytes(speed)}/s[/]")

    console.print()
    console.print(table)

    # Errors detail
    if summary.errors:
        console.print()
        error_panel_content = "\n".join(
            f"[red]✗[/] {err}" for err in summary.errors[:20]
        )
        if len(summary.errors) > 20:
            error_panel_content += f"\n[dim]...and {len(summary.errors) - 20} more[/]"
        console.print(
            Panel(
                error_panel_content,
                title="[bold red]⚠ Errors[/]",
                border_style="red",
                box=box.ROUNDED,
            )
        )

    # Final status
    console.print()
    if summary.files_failed == 0 and summary.files_wiped > 0:
        console.print(
            Panel(
                Align.center(
                    Text(
                        "✔ ALL FILES SANITIZED — DATA IRRECOVERABLE",
                        style="bold bright_green",
                    ),
                ),
                border_style="bright_green",
                box=box.DOUBLE_EDGE,
                padding=(1, 4),
            )
        )
    elif summary.files_wiped > 0:
        console.print(
            Panel(
                Align.center(
                    Text(
                        f"⚠ PARTIAL WIPE — {summary.files_wiped} wiped, {summary.files_failed} failed",
                        style="bold bright_yellow",
                    ),
                ),
                border_style="yellow",
                box=box.DOUBLE_EDGE,
                padding=(1, 4),
            )
        )
    else:
        console.print(
            Panel(
                Align.center(
                    Text("✗ NO FILES WERE WIPED", style="bold bright_red"),
                ),
                border_style="red",
                box=box.DOUBLE_EDGE,
                padding=(1, 4),
            )
        )


# ──────────────────────── Commands ─────────────────────────────

@app.command()
def wipe(
    target: str = typer.Argument(
        ..., help="Path to file or directory to securely wipe"
    ),
    confirm: bool = typer.Option(
        False, "--confirm", "-y", help="Skip confirmation prompt"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Preview files without wiping"
    ),
):
    """
    🧹 Securely wipe files using the DoD 5220.22-M standard (3-pass overwrite).

    Overwrites each file with zeros, ones, and random bytes, then scrubs
    metadata and deletes the file. Data becomes IRRECOVERABLE.
    """
    print_banner()

    target = os.path.abspath(target)

    # Validate target exists
    if not os.path.exists(target):
        console.print(f"\n  [bold red]✗ Target not found:[/] {target}")
        raise typer.Exit(code=1)

    # Collect files
    files = collect_files(target)

    if not files:
        console.print(f"\n  [bold yellow]⚠ No files found in:[/] {target}")
        raise typer.Exit(code=0)

    # Calculate total size
    total_size = sum(os.path.getsize(f) for f in files if os.path.exists(f))
    is_dir = os.path.isdir(target)

    # Show target info
    console.print()
    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column("Key", style="bold cyan")
    info_table.add_column("Value", style="white")
    info_table.add_row("Target", target)
    info_table.add_row("Type", "Directory (recursive)" if is_dir else "Single file")
    info_table.add_row("Files to wipe", str(len(files)))
    info_table.add_row("Total data", format_bytes(total_size))
    info_table.add_row("Method", "DoD 5220.22-M (3-pass)")
    info_table.add_row("Passes", "1) Zeros  2) Ones  3) Random")
    console.print(info_table)

    # Dry run — just list files
    if dry_run:
        console.print(
            "\n  [bold yellow]🔍 DRY RUN — no files will be modified:[/]\n"
        )
        for f in files[:50]:
            size = os.path.getsize(f) if os.path.exists(f) else 0
            console.print(f"    [dim]•[/] {f} [dim]({format_bytes(size)})[/]")
        if len(files) > 50:
            console.print(f"    [dim]...and {len(files) - 50} more files[/]")
        raise typer.Exit(code=0)

    # Confirmation
    if not confirm:
        console.print()
        console.print(
            Panel(
                "[bold red]⚠ WARNING: THIS ACTION IS IRREVERSIBLE ⚠[/]\n\n"
                "All targeted files will be overwritten 3 times and permanently deleted.\n"
                "[bold]Data CANNOT be recovered after this operation.[/]",
                border_style="bright_red",
                box=box.DOUBLE_EDGE,
                padding=(1, 2),
            )
        )
        console.print()
        user_confirm = typer.confirm(
            "  Are you sure you want to proceed?", default=False
        )
        if not user_confirm:
            console.print("\n  [bold cyan]Operation cancelled.[/]")
            raise typer.Exit(code=0)

    console.print()

    # ── Execute wipe with progress tracking ──
    summary = WipeSummary()
    summary.total_files = len(files)
    start_time = time.time()

    with Progress(
        SpinnerColumn("dots", style="cyan"),
        TextColumn("[bold]{task.description}[/]"),
        BarColumn(
            bar_width=40,
            complete_style="bright_green",
            finished_style="green",
        ),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[pass_info]}[/]"),
        TimeElapsedColumn(),
        console=console,
        expand=False,
    ) as progress:

        for file_idx, filepath in enumerate(files):
            basename = os.path.basename(filepath)
            display_name = basename[:30] + "…" if len(basename) > 30 else basename
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

            # Total work = file_size * 3 passes
            total_work = file_size * DOD_PASSES
            task_id = progress.add_task(
                f"[{file_idx + 1}/{len(files)}] {display_name}",
                total=total_work,
                pass_info="Starting...",
            )

            def make_progress_callback(tid):
                """Creates a closure for progress updates."""
                accumulated = {1: 0, 2: 0, 3: 0}

                def callback(fp, pass_num, bytes_done, total_bytes):
                    accumulated[pass_num] = bytes_done
                    total_done = sum(accumulated.values())
                    label, color = PASS_LABELS.get(pass_num, ("", "white"))
                    progress.update(
                        tid,
                        completed=total_done,
                        pass_info=f"[{color}]{label}[/]",
                    )

                return callback

            result = wipe_file(filepath, progress_callback=make_progress_callback(task_id))
            summary.results.append(result)

            if result.success:
                summary.files_wiped += 1
                summary.total_bytes_overwritten += result.bytes_written
                progress.update(
                    task_id,
                    completed=total_work,
                    pass_info="[bright_green]✔ Wiped[/]",
                )
            else:
                summary.files_failed += 1
                summary.errors.append(f"{result.filepath}: {result.error}")
                progress.update(
                    task_id,
                    completed=total_work,
                    pass_info=f"[bright_red]✗ {result.error[:30]}[/]",
                )

    summary.total_duration = time.time() - start_time

    # Remove empty directories if target was a directory
    if is_dir:
        for root, dirs, remaining_files in os.walk(target, topdown=False):
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except OSError:
                    pass
        try:
            os.rmdir(target)
        except OSError:
            pass

    # Show summary
    print_summary(summary)


@app.command()
def version():
    """Show version information."""
    print_banner()
    console.print(f"\n  Neutron-Wipe v{VERSION}")
    console.print("  DoD 5220.22-M Compliant Secure File Sanitization")
    console.print("  License: MIT — Authorized Use Only\n")


# ──────────────────────── Entry Point ──────────────────────────

if __name__ == "__main__":
    app()
