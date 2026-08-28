# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for WebRecon — builds a single standalone webrecon.exe.
# Build:  pyinstaller webrecon.spec   (output in dist/webrecon.exe)
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Bundle all non-Python data (payloads, wordlists, signatures, CVE DB,
# YAML templates, and the HTML report template) preserving package paths.
datas = collect_data_files("webrecon.data") + collect_data_files("webrecon.report")

# Make sure every check/recon/report submodule is included (they are imported
# statically, but this is a belt-and-braces guard).
hiddenimports = (collect_submodules("webrecon")
                 + ["dns", "dns.resolver", "dns.reversename"])

a = Analysis(
    ["webrecon/__main__.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],   # GUI is optional; keep the CLI exe small
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="webrecon",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,          # it's a CLI tool
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
