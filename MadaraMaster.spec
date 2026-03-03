# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

ROOT = Path(SPECPATH)

a = Analysis(
    [str(ROOT / 'madara.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[], 
    hiddenimports=[
        'aiofiles', 'aiofiles.os', 'aiofiles.threadpool', 'typer', 'click',
        'rich', 'rich.console', 'rich.live', 'rich.panel', 'rich.table',
        'rich.text', 'rich.align', 'rich.progress_bar', 'rich.box',
        'ctypes.wintypes', 'msvcrt', 'winreg',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
    optimize=2,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='MadaraMaster',
    icon=str(ROOT / 'assets' / 'madara.ico') if (ROOT / 'assets' / 'madara.ico').exists() else None,
    
    uac_admin=True,
    manifest=None,
    
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    onefile=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)