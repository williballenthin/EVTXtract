# -*- mode: python -*-

block_cipher = None

a = Analysis(
    ['evtxtract/main.py'],
     pathex=['evtxtract'],
     binaries=None,
     datas=None,
     hiddenimports=[],
     hookspath=None,
     runtime_hooks=None,
     excludes=["tkinter", "_tkinter", "Tkinter"],
     win_no_prefer_redirects=None,
     win_private_assemblies=None,
     cipher=None)

a.binaries = a.binaries - TOC([
 ('sqlite3.dll', None, None),
 ('tcl85.dll', None, None),
 ('tk85.dll', None, None),
 ('_sqlite3', None, None),
 ('_ssl', None, None),
 ('_tkinter', None, None)])

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          exclude_binaries=False,
          name='evtxtract',
          #icon='resources/icon.ico',
          debug=False,
          strip=None,
          upx=True,
          console=True )

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='evtxtract-dat')
