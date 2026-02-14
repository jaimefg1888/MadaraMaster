#!/usr/bin/env python3
"""
MadaraMaster — CLI Interface
==============================
Professional cyberpunk-themed CLI for secure file sanitization.
Implements DoD 5220.22-M with real-time progress visualization.
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
    name="madaramaster",
    help="🧹 MadaraMaster — DoD 5220.22-M Secure File Sanitization",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

VERSION = "2.2.0"

# ──────────────────────── i18n — Language System ───────────────

LANG = {
    "EN": {
        # -- Interactive session --
        "session_title":      "Interactive Session Mode",
        "session_hint":       "n\Enter the path or drag and drop a file or folder, then press Enter.",
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
        "all_sanitized":      "✔ ALL FILES SANITIZED — DATA IRRECOVERABLE",
        "partial_wipe":       "⚠ PARTIAL WIPE — {wiped} wiped, {failed} failed",
        "no_files_wiped":     "✗ NO FILES WERE WIPED",
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
        "session_hint":       "n\Arrastra un archivo o carpeta y pulsa Enter.",
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
        "all_sanitized":      "✔ TODOS LOS ARCHIVOS SANITIZADOS — DATOS IRRECUPERABLES",
        "partial_wipe":       "⚠ BORRADO PARCIAL — {wiped} borrados, {failed} fallidos",
        "no_files_wiped":     "✗ NO SE BORRÓ NINGÚN ARCHIVO",
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


def get_pass_labels() -> dict:
    """Returns pass labels in the current language."""
    return {
        1: (T("pass_1"), "bright_red"),
        2: (T("pass_2"), "bright_yellow"),
        3: (T("pass_3"), "bright_green"),
    }


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
                                                           
   MadaraMaster v2.2 • Created by jaimefg1888 • DoD 5220.22-M
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


def format_bytes(b: int) -> str:
    """Formats bytes into human-readable units."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024.0:
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} PB"


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
        console.print(
            Panel(
                Align.center(
                    Text(T("all_sanitized"), style="bold bright_green"),
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

    # ── Execute wipe with progress tracking ──
    pass_labels = get_pass_labels()
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
                pass_info=T("starting"),
            )

            def make_progress_callback(tid):
                """Creates a closure for progress updates."""
                accumulated = {1: 0, 2: 0, 3: 0}

                def callback(fp, pass_num, bytes_done, total_bytes):
                    accumulated[pass_num] = bytes_done
                    total_done = sum(accumulated.values())
                    label, color = pass_labels.get(pass_num, ("", "white"))
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
                    pass_info=f"[bright_green]{T('wiped')}[/]",
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
    console.print(f"\n  MadaraMaster v{VERSION}")
    console.print(f"  {T('version_desc')}")
    console.print(f"  {T('version_license')}\n")


# ──────────────────────── Interactive Session ──────────────────

def interactive_session():
    """
    Interactive session mode: infinite loop for drag-and-drop file wiping.
    Invoked when the script runs without arguments.
    """
    print_banner()
    console.print(f"  [bold cyan]{T('session_title')}[/]")
    hint = T('session_hint')
    if hint:
        console.print(f"  {hint}")
    console.print(f"  [dim]{T('session_exit_hint')}[/]\n")

    while True:
        try:
            raw_input = input(T("session_prompt"))
        except (EOFError, KeyboardInterrupt):
            console.print(f"\n  [bold cyan]{T('session_ended')}[/]")
            break

        # Detect --force flag BEFORE stripping quotes (preserves paths with spaces)
        skip_confirm = False
        if raw_input.rstrip().endswith("--force"):
            raw_input = raw_input.rstrip()[:-len("--force")]
            skip_confirm = True

        # Input sanitization: strip whitespace + remove surrounding quotes
        cleaned = raw_input.strip().strip("'").strip('"').strip()

        if not cleaned:
            continue

        if cleaned.lower() in EXIT_KEYWORDS[current_lang]:
            console.print(f"\n  [bold cyan]{T('session_goodbye')}[/]")
            break

        # Validate path exists
        target = os.path.abspath(cleaned)
        if not os.path.exists(target):
            console.print(f"  [bold red]{T('path_not_found')}[/] {target}")
            continue

        # Confirmation (unless --force turbo mode)
        if not skip_confirm:
            if not confirm_action():
                console.print(f"  [bold cyan]{T('op_cancelled')}[/]")
                continue

        # Invoke the wipe command via sys.argv (--confirm skips Typer's own prompt)
        sys.argv = ["madara.py", "wipe", target, "--confirm"]
        try:
            app(standalone_mode=False)
        except SystemExit:
            pass


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
