# -*- mode: python ; coding: utf-8 -*-

# Windows-oriented PyInstaller build for the ZFS Specialist.
# Build with: pyinstaller --noconfirm --clean ZFSSpecialist.spec

a = Analysis(
    ['src/unzfs.py'],
    pathex=['.'],
    binaries=[('dll_source/lzo_bridge.dll', '.')],
    datas=[
        ('BZONE.ttf', '.'),
        ('branding/app_icon.ico', 'branding'),
        ('branding/app_icon.png', 'branding'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['branding/pyinstaller_icon_hook.py'],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='zfs_specialist',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='branding/app_icon.ico',
)
