#!/usr/bin/env python3
"""
MadaraMaster — CLI Interface v3.0
===================================
Professional cyberpunk-themed CLI for secure file sanitization.
Implements DoD 5220.22-M with real-time Live Dashboard visualization.
Bilingual support: English (EN) and Spanish (ES).

Usage:
    python madara.py                          # Interactive session mode
    python madara.py wipe <TARGET>            # Wipe a file or directory
    python madara.py wipe <TARGET> --confirm  # Skip confirmation prompt
    python madara.py wipe <TARGET> --dry-run  # Preview without deleting

Author : MadaraMaster Team
License: MIT — Authorized Data Sanitization Use Only
"""

import os
import sys
import time
import collections
from typing import Optional

import typer
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.live import Live
from rich.progress_bar import ProgressBar
from rich import box

from wiper import (
    wipe_file,
    wipe_directory,
    collect_files,
    WipeResult,
    WipeSummary,
    WipeTelemetry,
    DOD_PASSES,
)
from utils import format_bytes

# ──────────────────────── App Setup ────────────────────────────

app = typer.Typer(
    name="madaramaster",
    help="🧹 MadaraMaster — DoD 5220.22-M Secure File Sanitization",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

VERSION = "3.0.0"

# ──────────────────────── i18n — Language System ───────────────

LANG = {
    "EN": {
        # -- Interactive session --
        "session_title":      "Interactive Session Mode",
        "session_hint":       "Drag or type the path of one or more files/folders and press Enter.",
        "session_exit_hint":  "Type [bold]exit[/bold] or [bold]close[/bold] to quit.",
        "session_prompt":     "❱❱❱ ",
        "session_ended":      "Session ended.",
        "session_goodbye":    "👋 Session ended. See you later.",
        "path_not_found":     "✗ Path not found:",
        # -- Wipe command --
        "target_not_found":   "✗ Target not found:",
        "no_files_found":     "⚠ No files found in:",
        "type_dir":           "Directory (recursive)",
        "type_file":          "Single file",
        "lbl_target":         "Target",
        "lbl_type":           "Type",
        "files_to_wipe":      "Files to wipe",
        "total_data":         "Total data",
        "method":             "Method",
        "passes":             "Passes",
        "pass_values":        "1) Zeros  2) Ones  3) Random",
        "dry_run_title":      "🔍 DRY RUN — no files will be modified:",
        "more_files":         "...and {n} more files",
        "warning_title":      "⚠ WARNING: THIS ACTION IS IRREVERSIBLE ⚠",
        "warning_body":       "All targeted files will be overwritten 3 times and permanently deleted.\n[bold]Data CANNOT be recovered after this operation.[/]",
        "confirm_prompt":     "  Are you sure you want to proceed?",
        "confirm_msg":        "Are you sure? [y/N]: ",
        "op_cancelled":       "Operation cancelled.",
        "starting":           "Starting...",
        # -- Preview table --
        "preview_title":      "📋 FILES TO DESTROY",
        "preview_name":       "Name",
        "preview_size":       "Size",
        "preview_type":       "Type",
        "preview_total":      "TOTAL",
        # -- Dashboard --
        "dash_header":        "🛡️  MADARA MASTER v3.0 | SECURITY DAEMON",
        "dash_file":          "📁 File",
        "dash_algorithm":     "🔒 Algorithm",
        "dash_status":        "🔄 Status",
        "dash_pass_1":        "Pass 1/3 — Overwriting with 0x00 (Zeros)...",
        "dash_pass_2":        "Pass 2/3 — Overwriting with 0xFF (Ones)...",
        "dash_pass_3":        "Pass 3/3 — Overwriting with Random Bytes...",
        "dash_scrubbing":     "🧹 Scrubbing metadata & deleting...",
        "dash_progress":      "📊 Global Progress",
        "dash_speed":         "🚀 Speed",
        "dash_written":       "💾 Effective Write",
        "dash_file_counter":  "📂 File",
        # -- Summary --
        "summary_title":      "🧹 WIPE SUMMARY",
        "metric":             "Metric",
        "value":              "Value",
        "total_targeted":     "Total Files Targeted",
        "files_wiped_ok":     "Files Wiped Successfully",
        "files_failed":       "Files Failed",
        "total_overwritten":  "Total Bytes Overwritten",
        "effective_written":  "Effective Data Written (3 passes)",
        "total_duration":     "Total Duration",
        "avg_speed":          "Average Write Speed",
        "errors_title":       "⚠ Errors",
        "more_errors":        "...and {n} more",
        "all_sanitized_one":  "✔ {n} FILE DELETED — DATA IRRECOVERABLE",
        "all_sanitized_many": "✔ {n} FILES DELETED — DATA IRRECOVERABLE",
        "partial_wipe":       "⚠ PARTIAL WIPE — {wiped} wiped, {failed} failed",
        "no_files_wiped":     "✗ NO FILES WERE WIPED",
        # -- Completion --
        "completion_msg":     "[v3.0] SANITIZATION VERIFIED — ZERO RECOVERY",
        # -- Pass labels --
        "pass_1":             "Pass 1/3 · Zeros",
        "pass_2":             "Pass 2/3 · Ones",
        "pass_3":             "Pass 3/3 · Random",
        "wiped":              "✔ Wiped",
        # -- Version --
        "version_desc":       "DoD 5220.22-M Compliant Secure File Sanitization",
        "version_license":    "License: MIT — Authorized Use Only",
    },
    "ES": {
        # -- Interactive session --
        "session_title":      "Modo Sesión Interactiva",
        "session_hint":       "Arrastra o escribe la ruta de uno o más archivos/carpetas y pulsa Enter.",
        "session_exit_hint":  "Escribe [bold]salir[/bold] o [bold]cerrar[/bold] para salir.",
        "session_prompt":     "❱❱❱ ",
        "session_ended":      "Sesión terminada.",
        "session_goodbye":    "👋 Sesión terminada. Hasta pronto.",
        "path_not_found":     "✗ Ruta no encontrada:",
        # -- Wipe command --
        "target_not_found":   "✗ Objetivo no encontrado:",
        "no_files_found":     "⚠ No se encontraron archivos en:",
        "type_dir":           "Directorio (recursivo)",
        "type_file":          "Archivo individual",
        "lbl_target":         "Objetivo",
        "lbl_type":           "Tipo",
        "files_to_wipe":      "Archivos a borrar",
        "total_data":         "Datos totales",
        "method":             "Método",
        "passes":             "Pases",
        "pass_values":        "1) Ceros  2) Unos  3) Aleatorio",
        "dry_run_title":      "🔍 SIMULACIÓN — no se modificará ningún archivo:",
        "more_files":         "...y {n} archivos más",
        "warning_title":      "⚠ ADVERTENCIA: ESTA ACCIÓN ES IRREVERSIBLE ⚠",
        "warning_body":       "Todos los archivos serán sobrescritos 3 veces y eliminados permanentemente.\n[bold]Los datos NO se podrán recuperar tras esta operación.[/]",
        "confirm_prompt":     "  ¿Estás seguro de que deseas continuar?",
        "confirm_msg":        "¿Estás seguro? [s/N]: ",
        "op_cancelled":       "Operación cancelada.",
        "starting":           "Iniciando...",
        # -- Preview table --
        "preview_title":      "📋 ARCHIVOS A DESTRUIR",
        "preview_name":       "Nombre",
        "preview_size":       "Tamaño",
        "preview_type":       "Tipo",
        "preview_total":      "TOTAL",
        # -- Dashboard --
        "dash_header":        "🛡️  MADARA MASTER v3.0 | SECURITY DAEMON",
        "dash_file":          "📁 Archivo",
        "dash_algorithm":     "🔒 Algoritmo",
        "dash_status":        "🔄 Estado",
        "dash_pass_1":        "Pase 1/3 — Sobrescribiendo con 0x00 (Ceros)...",
        "dash_pass_2":        "Pase 2/3 — Sobrescribiendo con 0xFF (Unos)...",
        "dash_pass_3":        "Pase 3/3 — Sobrescribiendo con Bytes Aleatorios...",
        "dash_scrubbing":     "🧹 Limpiando metadatos y eliminando...",
        "dash_progress":      "📊 Progreso Global",
        "dash_speed":         "🚀 Velocidad",
        "dash_written":       "💾 Escritura Efectiva",
        "dash_file_counter":  "📂 Archivo",
        # -- Summary --
        "summary_title":      "🧹 RESUMEN DE BORRADO",
        "metric":             "Métrica",
        "value":              "Valor",
        "total_targeted":     "Total Archivos Objetivo",
        "files_wiped_ok":     "Archivos Borrados con Éxito",
        "files_failed":       "Archivos Fallidos",
        "total_overwritten":  "Total Bytes Sobrescritos",
        "effective_written":  "Datos Efectivos Escritos (3 pases)",
        "total_duration":     "Duración Total",
        "avg_speed":          "Velocidad Media de Escritura",
        "errors_title":       "⚠ Errores",
        "more_errors":        "...y {n} más",
        "all_sanitized_one":  "✔ {n} ARCHIVO ELIMINADO — DATOS IRRECUPERABLES",
        "all_sanitized_many": "✔ {n} ARCHIVOS ELIMINADOS — DATOS IRRECUPERABLES",
        "partial_wipe":       "⚠ BORRADO PARCIAL — {wiped} borrados, {failed} fallidos",
        "no_files_wiped":     "✗ NO SE BORRÓ NINGÚN ARCHIVO",
        # -- Completion --
        "completion_msg":     "[v3.0] SANITIZACIÓN VERIFICADA — ZERO RECOVERY",
        # -- Pass labels --
        "pass_1":             "Pase 1/3 · Ceros",
        "pass_2":             "Pase 2/3 · Unos",
        "pass_3":             "Pase 3/3 · Aleatorio",
        "wiped":              "✔ Borrado",
        # -- Version --
        "version_desc":       "Sanitización Segura de Archivos — Norma DoD 5220.22-M",
        "version_license":    "Licencia: MIT — Uso Autorizado Únicamente",
    },
}

# Session language — set by select_language() at startup
current_lang = "EN"

# Exit keywords — language-specific (only current language works)
EXIT_KEYWORDS = {
    "EN": frozenset(["exit", "close", "quit"]),
    "ES": frozenset(["salir", "cerrar"]),
}

# Universal confirmation acceptance set (works in both EN and ES)
CONFIRM_YES = frozenset(["y", "yes", "s", "si"])


def T(key: str, **kwargs) -> str:
    """Get translated text for the current language, with optional format params."""
    text = LANG[current_lang].get(key, key)
    return text.format(**kwargs) if kwargs else text


def confirm_action() -> bool:
    """Bilingual confirmation prompt. Accepts y/yes/s/si regardless of language."""
    answer = input(T("confirm_msg")).lower().strip()
    return answer in CONFIRM_YES


# ──────────────────────── Banner ───────────────────────────────

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
                                                            
   MadaraMaster v3.0 • Created by jaimefg1888 • DoD 5220.22-M
"""


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


def select_language() -> str:
    """
    Prompts the user to select a language.
    Loops until a valid option is entered. Defaults to EN on empty input.
    """
    while True:
        choice = input("Select Language / Seleccione Idioma [1: EN | 2: ES]: ").strip()
        if choice in ("", "1"):
            return "EN"
        elif choice == "2":
            return "ES"
        # Invalid input → repeat


def print_summary(summary: WipeSummary):
    """Displays the post-wipe summary table (bilingual)."""
    table = Table(
        title=f"[bold bright_cyan]{T('summary_title')}[/]",
        box=box.DOUBLE_EDGE,
        border_style="bright_cyan",
        padding=(0, 2),
        show_lines=True,
    )
    table.add_column(T("metric"), style="bold white", min_width=25)
    table.add_column(T("value"), style="bold", min_width=20, justify="right")

    # Files
    success_style = "bright_green" if summary.files_wiped > 0 else "dim"
    fail_style = "bright_red" if summary.files_failed > 0 else "bright_green"

    table.add_row(T("total_targeted"), f"[cyan]{summary.total_files}[/]")
    table.add_row(T("files_wiped_ok"), f"[{success_style}]{summary.files_wiped}[/]")
    table.add_row(T("files_failed"), f"[{fail_style}]{summary.files_failed}[/]")
    table.add_row("─" * 25, "─" * 20)

    # Bytes
    total_overwritten = summary.total_bytes_overwritten
    table.add_row(
        T("total_overwritten"),
        f"[bright_yellow]{total_overwritten:,}[/] [dim]({format_bytes(total_overwritten)})[/]"
    )
    table.add_row(
        T("effective_written"),
        f"[bright_yellow]{format_bytes(total_overwritten)}[/]"
    )
    table.add_row("─" * 25, "─" * 20)

    # Time
    table.add_row(T("total_duration"), f"[bright_magenta]{summary.total_duration:.3f}s[/]")

    if total_overwritten > 0 and summary.total_duration > 0:
        speed = total_overwritten / summary.total_duration
        table.add_row(T("avg_speed"), f"[dim]{format_bytes(speed)}/s[/]")

    console.print()
    console.print(table)

    # Errors detail
    if summary.errors:
        console.print()
        error_panel_content = "\n".join(
            f"[red]✗[/] {err}" for err in summary.errors[:20]
        )
        if len(summary.errors) > 20:
            error_panel_content += f"\n[dim]{T('more_errors', n=len(summary.errors) - 20)}[/]"
        console.print(
            Panel(
                error_panel_content,
                title=f"[bold red]{T('errors_title')}[/]",
                border_style="red",
                box=box.ROUNDED,
            )
        )

    # Final status
    console.print()
    if summary.files_failed == 0 and summary.files_wiped > 0:
        key = "all_sanitized_one" if summary.files_wiped == 1 else "all_sanitized_many"
        console.print(
            Panel(
                Align.center(
                    Text(T(key, n=summary.files_wiped), style="bold bright_green"),
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
                        T("partial_wipe", wiped=summary.files_wiped, failed=summary.files_failed),
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
                    Text(T("no_files_wiped"), style="bold bright_red"),
                ),
                border_style="red",
                box=box.DOUBLE_EDGE,
                padding=(1, 4),
            )
        )


# ──────────────────────── Live Dashboard ───────────────────────

class SpeedTracker:
    """
    Calculates write speed using a 2-second moving average window.
    Avoids jumpy speed readings by smoothing over recent samples.
    """

    def __init__(self, window_seconds: float = 2.0):
        self._window = window_seconds
        self._samples: collections.deque = collections.deque()

    def record(self, bytes_written: int, timestamp: float = None):
        """Record a cumulative bytes_written sample."""
        ts = timestamp or time.time()
        self._samples.append((ts, bytes_written))
        # Prune old samples outside the window
        cutoff = ts - self._window
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

    def get_speed(self) -> float:
        """Returns bytes/second as a moving average over the window."""
        if len(self._samples) < 2:
            return 0.0
        oldest_ts, oldest_bytes = self._samples[0]
        newest_ts, newest_bytes = self._samples[-1]
        dt = newest_ts - oldest_ts
        if dt <= 0:
            return 0.0
        return (newest_bytes - oldest_bytes) / dt


def _get_pass_status(pass_number: int) -> str:
    """Returns the i18n dashboard status string for a given pass."""
    return T(f"dash_pass_{pass_number}")


def _build_dashboard(
    telemetry: WipeTelemetry,
    speed_tracker: SpeedTracker,
    file_index: int,
    total_files: int,
) -> Panel:
    """
    Constructs the full Live Dashboard layout as a Rich Panel.

    Layout:
        ┌─ Header ──────────────────────────────────────┐
        │  🛡️  MADARA MASTER v3.0 | SECURITY DAEMON     │
        ├─ File Info ────────────────────────────────────┤
        │  📁 File: ...    🔒 Algorithm: ...   🔄 ...   │
        ├─ Metrics ──────────────────────────────────────┤
        │  📊 Progress   🚀 Speed   💾 Written          │
        └────────────────────────────────────────────────┘
    """
    # ── Header ──
    header = Text(T("dash_header"), style="bold bright_cyan")

    # ── File Info Panel ──
    basename = os.path.basename(telemetry.current_file) if telemetry.current_file else "—"
    display_name = basename[:45] + "…" if len(basename) > 45 else basename

    if telemetry.current_pass > 0:
        status_text = _get_pass_status(telemetry.current_pass)
    elif telemetry.finished:
        status_text = T("dash_scrubbing")
    else:
        status_text = T("starting")

    info_table = Table(box=None, show_header=False, padding=(0, 2), expand=True)
    info_table.add_column("Key", style="bold white", ratio=1)
    info_table.add_column("Value", style="bright_white", ratio=3)
    info_table.add_row(T("dash_file"), f"[bright_yellow]{display_name}[/]")
    info_table.add_row(T("dash_algorithm"), "[dim]DoD 5220.22-M (3 Passes)[/]")
    info_table.add_row(T("dash_status"), f"[bright_cyan]{status_text}[/]")

    if total_files > 1:
        info_table.add_row(
            T("dash_file_counter"),
            f"[bright_magenta]{file_index}/{total_files}[/]"
        )

    # ── Metrics Grid ──
    progress_pct = telemetry.global_progress * 100
    speed = speed_tracker.get_speed()
    total_target = telemetry.total_target_bytes

    # Build the progress bar
    bar = ProgressBar(
        total=100,
        completed=progress_pct,
        width=40,
        complete_style="bright_green" if progress_pct < 100 else "green",
        finished_style="bold green",
    )

    metrics_table = Table(box=None, show_header=False, padding=(0, 2), expand=True)
    metrics_table.add_column("Icon", style="bold", width=22)
    metrics_table.add_column("Data", ratio=3)

    # Progress row
    progress_text = Group(
        bar,
        Text(f" {progress_pct:.1f}%", style="bold bright_green"),
    )
    metrics_table.add_row(T("dash_progress"), progress_text)

    # Speed row
    speed_str = f"{format_bytes(int(speed))}/s" if speed > 0 else "—"
    metrics_table.add_row(
        T("dash_speed"),
        Text(speed_str, style="bold bright_yellow"),
    )

    # Written row
    written_str = (
        f"{format_bytes(telemetry.bytes_written_total)} / "
        f"{format_bytes(total_target)}"
    )
    metrics_table.add_row(
        T("dash_written"),
        Text(written_str, style="bold bright_magenta"),
    )

    # ── Assemble ──
    inner = Group(
        Align.center(header),
        Text(""),  # spacer
        Panel(info_table, border_style="dim cyan", box=box.ROUNDED, padding=(0, 1)),
        Text(""),  # spacer
        Panel(metrics_table, border_style="dim cyan", box=box.ROUNDED, padding=(0, 1)),
    )

    return Panel(
        inner,
        border_style="bright_cyan",
        box=box.HEAVY,
        padding=(1, 2),
    )


def _print_completion_panel():
    """Renders the final green neon completion panel after Live stops."""
    console.print()
    console.print(
        Panel(
            Align.center(
                Text(T("completion_msg"), style="bold bright_green on black"),
            ),
            border_style="bright_green",
            box=box.DOUBLE_EDGE,
            padding=(1, 4),
        )
    )
    console.print()


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
        console.print(f"\n  [bold red]{T('target_not_found')}[/] {target}")
        raise typer.Exit(code=1)

    # Collect files
    files = collect_files(target)

    if not files:
        console.print(f"\n  [bold yellow]{T('no_files_found')}[/] {target}")
        raise typer.Exit(code=0)

    # Calculate total size
    total_size = sum(os.path.getsize(f) for f in files if os.path.exists(f))
    is_dir = os.path.isdir(target)

    # Show target info
    console.print()
    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column("Key", style="bold cyan")
    info_table.add_column("Value", style="white")
    info_table.add_row(T("lbl_target"), target)
    info_table.add_row(T("lbl_type"), T("type_dir") if is_dir else T("type_file"))
    info_table.add_row(T("files_to_wipe"), str(len(files)))
    info_table.add_row(T("total_data"), format_bytes(total_size))
    info_table.add_row(T("method"), "DoD 5220.22-M (3-pass)")
    info_table.add_row(T("passes"), T("pass_values"))
    console.print(info_table)

    # Dry run — just list files
    if dry_run:
        console.print(
            f"\n  [bold yellow]{T('dry_run_title')}[/]\n"
        )
        for f in files[:50]:
            size = os.path.getsize(f) if os.path.exists(f) else 0
            console.print(f"    [dim]•[/] {f} [dim]({format_bytes(size)})[/]")
        if len(files) > 50:
            console.print(f"    [dim]{T('more_files', n=len(files) - 50)}[/]")
        raise typer.Exit(code=0)

    # Confirmation
    if not confirm:
        console.print()
        console.print(
            Panel(
                f"[bold red]{T('warning_title')}[/]\n\n"
                f"{T('warning_body')}",
                border_style="bright_red",
                box=box.DOUBLE_EDGE,
                padding=(1, 2),
            )
        )
        console.print()
        user_confirm = typer.confirm(
            T("confirm_prompt"), default=False
        )
        if not user_confirm:
            console.print(f"\n  [bold cyan]{T('op_cancelled')}[/]")
            raise typer.Exit(code=0)

    console.print()

    # ── Execute wipe with Live Dashboard ──
    summary = WipeSummary()
    summary.total_files = len(files)
    start_time = time.time()

    telemetry = WipeTelemetry()
    speed_tracker = SpeedTracker(window_seconds=2.0)

    # Accumulated bytes across ALL files for multi-file global tracking
    global_bytes_written = 0

    with Live(
        _build_dashboard(telemetry, speed_tracker, 0, len(files)),
        console=console,
        refresh_per_second=12,
        transient=True,
    ) as live:

        for file_idx, filepath in enumerate(files, start=1):
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

            # Reset telemetry for this file
            telemetry.start_time = time.time()
            telemetry.current_pass = 0
            telemetry.file_size = file_size
            telemetry.current_file = filepath
            telemetry.bytes_written_total = 0
            telemetry.bytes_written_current_pass = 0
            telemetry.finished = False

            speed_tracker = SpeedTracker(window_seconds=2.0)

            def make_callback():
                """Creates a closure for per-chunk progress updates."""
                accumulated = {1: 0, 2: 0, 3: 0}

                def callback(fp, pass_num, bytes_done, total_bytes):
                    accumulated[pass_num] = bytes_done
                    telemetry.current_pass = pass_num
                    telemetry.bytes_written_current_pass = bytes_done
                    telemetry.bytes_written_total = sum(accumulated.values())

                    speed_tracker.record(telemetry.bytes_written_total)

                    # Update the live display
                    live.update(
                        _build_dashboard(telemetry, speed_tracker, file_idx, len(files))
                    )

                return callback

            result = wipe_file(filepath, progress_callback=make_callback())
            summary.results.append(result)

            if result.success:
                summary.files_wiped += 1
                summary.total_bytes_overwritten += result.bytes_written
                global_bytes_written += result.bytes_written

                # Final update for this file — mark finished
                telemetry.finished = True
                telemetry.bytes_written_total = file_size * DOD_PASSES
                live.update(
                    _build_dashboard(telemetry, speed_tracker, file_idx, len(files))
                )
            else:
                summary.files_failed += 1
                summary.errors.append(f"{result.filepath}: {result.error}")

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

    # ── Completion: static green neon panel ──
    _print_completion_panel()

    # Show detailed summary
    print_summary(summary)


@app.command()
def version():
    """Show version information."""
    print_banner()
    console.print(f"\n  MadaraMaster v{VERSION}")
    console.print(f"  {T('version_desc')}")
    console.print(f"  {T('version_license')}\n")


# ──────────────────────── Interactive Session ──────────────────

def _parse_multi_paths(raw: str) -> list[str]:
    """
    Parses a raw input string that may contain one or more paths.

    Handles:
        - Single path:           C:\\Users\\docs\\secret.txt
        - Quoted path:           "C:\\Users\\My Docs\\file.txt"
        - Multiple drag-n-drop:  "C:\\a.txt" "C:\\b.txt" "C:\\c.txt"
        - Mixed:                 C:\\a.txt "C:\\My Dir\\b.txt"
    """
    paths: list[str] = []
    i = 0
    raw = raw.strip()

    while i < len(raw):
        # Skip whitespace between paths
        if raw[i] in (' ', '\t'):
            i += 1
            continue

        # Quoted path
        if raw[i] == '"':
            end = raw.find('"', i + 1)
            if end == -1:
                # Unterminated quote — take rest as path
                paths.append(raw[i + 1:].strip())
                break
            paths.append(raw[i + 1:end])
            i = end + 1
        elif raw[i] == "'":
            end = raw.find("'", i + 1)
            if end == -1:
                paths.append(raw[i + 1:].strip())
                break
            paths.append(raw[i + 1:end])
            i = end + 1
        else:
            # Unquoted path — runs until next space (unless it looks like a drive letter path)
            # On Windows, paths with spaces won't work unquoted with multi-file, but single file is fine
            end = i
            while end < len(raw) and raw[end] not in ('"', "'"):
                end += 1
            paths.append(raw[i:end].strip())
            i = end

    # Filter empty strings
    return [p for p in paths if p]


def _print_file_preview(targets: list[str]):
    """Displays a rich preview table of the files about to be wiped."""
    table = Table(
        title=f"[bold bright_cyan]{T('preview_title')}[/]",
        box=box.ROUNDED,
        border_style="bright_cyan",
        padding=(0, 1),
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column(T("preview_name"), style="bold white", ratio=3)
    table.add_column(T("preview_size"), style="bright_yellow", justify="right", min_width=12)
    table.add_column(T("preview_type"), style="dim cyan", min_width=10)

    total_size = 0
    for idx, target in enumerate(targets, start=1):
        name = os.path.basename(target) or target
        if os.path.isdir(target):
            # Count files inside
            file_count = sum(len(files) for _, _, files in os.walk(target))
            size = sum(
                os.path.getsize(os.path.join(r, f))
                for r, _, fs in os.walk(target)
                for f in fs
                if os.path.exists(os.path.join(r, f))
            )
            type_str = f"📁 {T('type_dir')}"
            name_str = f"{name}/ [dim]({file_count} files)[/]"
        else:
            size = os.path.getsize(target) if os.path.exists(target) else 0
            type_str = f"📄 {T('type_file')}"
            name_str = name

        total_size += size
        table.add_row(str(idx), name_str, format_bytes(size), type_str)

    # Footer row with total
    table.add_row(
        "",
        f"[bold]{T('preview_total')}[/]",
        f"[bold bright_green]{format_bytes(total_size)}[/]",
        "",
    )

    console.print()
    console.print(table)
    console.print()


def _print_session_hints():
    """Prints the session drag-and-drop and exit hints."""
    hint = T('session_hint')
    if hint:
        console.print(f"  {hint}")
    console.print(f"  [dim]{T('session_exit_hint')}[/]\n")


def _read_all_pasted_input(prompt: str) -> str:
    """
    Reads input that may span multiple pasted lines.

    On Windows, bypasses Python's input() entirely and reads character-by-
    character from the console buffer using msvcrt.getwch(). After each
    Enter key, waits 150ms for more pasted data. Since getwch() and kbhit()
    both operate on the raw console buffer, this correctly captures all
    lines from a multi-line paste.

    On non-Windows, falls back to standard input().
    """
    if sys.platform != "win32":
        return input(prompt)

    import msvcrt

    # Print prompt manually (no newline)
    sys.stdout.write(prompt)
    sys.stdout.flush()

    lines: list[str] = []
    current: list[str] = []

    while True:
        ch = msvcrt.getwch()

        if ch in ('\r', '\n'):
            # Enter pressed — save current line
            sys.stdout.write('\n')
            sys.stdout.flush()
            lines.append(''.join(current))
            current = []

            # Wait up to 150ms for more pasted input
            deadline = time.time() + 0.15
            got_more = False
            while time.time() < deadline:
                if msvcrt.kbhit():
                    got_more = True
                    break
                time.sleep(0.01)

            if not got_more:
                break  # No more input — user actually pressed Enter

            # More data detected — continue reading the next line

        elif ch == '\x03':  # Ctrl+C
            raise KeyboardInterrupt
        elif ch == '\x1a':  # Ctrl+Z
            raise EOFError
        elif ch == '\b':    # Backspace
            if current:
                current.pop()
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        elif ch in ('\x00', '\xe0'):  # Special key prefix (arrows, F-keys)
            msvcrt.getwch()  # Consume the second byte and ignore
        else:
            current.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()

    # Handle any trailing partial line
    remaining = ''.join(current).strip()
    if remaining:
        lines.append(remaining)

    # Filter empty lines
    lines = [l for l in lines if l.strip()]

    if not lines:
        return ""

    if len(lines) == 1:
        return lines[0]

    # Multiple lines: wrap each in quotes for _parse_multi_paths
    parts = []
    for line in lines:
        clean = line.strip().strip("'").strip('"').strip()
        if clean:
            parts.append(f'"{clean}"')

    return " ".join(parts)


def interactive_session():
    """
    Interactive session mode: infinite loop for drag-and-drop file wiping.
    Supports multiple files at once. Invoked when the script runs without arguments.
    """
    print_banner()
    console.print(f"  [bold cyan]{T('session_title')}[/]\n")
    _print_session_hints()

    while True:
        try:
            raw_input = _read_all_pasted_input(T("session_prompt"))
        except (EOFError, KeyboardInterrupt):
            console.print(f"\n  [bold cyan]{T('session_ended')}[/]")
            break

        # Detect --force flag BEFORE parsing paths
        skip_confirm = False
        if raw_input.rstrip().endswith("--force"):
            raw_input = raw_input.rstrip()[:-len("--force")]
            skip_confirm = True

        # Check for exit first (before multi-path parsing)
        stripped = raw_input.strip().strip("'").strip('"').strip()
        if not stripped:
            continue

        if stripped.lower() in EXIT_KEYWORDS[current_lang]:
            console.print(f"\n  [bold cyan]{T('session_goodbye')}[/]")
            break

        # Parse multiple paths from input
        parsed_paths = _parse_multi_paths(raw_input)
        if not parsed_paths:
            continue

        # Resolve and validate all paths
        valid_targets: list[str] = []
        for p in parsed_paths:
            target = os.path.abspath(p.strip())
            if os.path.exists(target):
                valid_targets.append(target)
            else:
                console.print(f"  [bold red]{T('path_not_found')}[/] {target}")

        if not valid_targets:
            continue

        # Show preview table of all targets
        _print_file_preview(valid_targets)

        # Confirmation (unless --force turbo mode)
        if not skip_confirm:
            if not confirm_action():
                console.print(f"  [bold cyan]{T('op_cancelled')}[/]")
                console.print()
                _print_session_hints()
                continue

        # Wipe each target
        for target in valid_targets:
            sys.argv = ["madara.py", "wipe", target, "--confirm"]
            try:
                app(standalone_mode=False)
            except SystemExit:
                pass

        # Re-display session hints after wipe completes
        console.print()
        _print_session_hints()


# ──────────────────────── Windows Context Menu ────────────────

def install_context_menu():
    """Installs MadaraMaster into the Windows right-click context menu."""
    if sys.platform != "win32":
        print("Error: Context menu installation is only available on Windows.")
        return

    import winreg

    try:
        key_path = r"*\shell\MadaraMaster"
        command_path = key_path + r"\command"
        script_path = os.path.abspath(__file__)
        cmd = f'"{ sys.executable}" "{script_path}" wipe "%1"'

        # Create shell key with display name and icon
        key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "Wipe with MadaraMaster")
        winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, sys.executable)
        winreg.CloseKey(key)

        # Create command key
        cmd_key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, command_path)
        winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, cmd)
        winreg.CloseKey(cmd_key)

        print("✔ Context menu installed successfully.")
        print(f"  Command: {cmd}")
    except PermissionError:
        print("Error: Run CMD as Administrator to install context menu.")
    except Exception as e:
        print(f"Error: {e}")


# ──────────────────────── Entry Point ──────────────────────────

if __name__ == "__main__":
    # Handle context menu installation before Typer
    if len(sys.argv) > 1 and sys.argv[1] == "install-right-click":
        install_context_menu()
        sys.exit(0)

    if len(sys.argv) <= 1:
        # Interactive mode: select language first, then start session
        current_lang = select_language()
        interactive_session()
    else:
        # CLI mode: default to EN for standard CLI usage
        app()
