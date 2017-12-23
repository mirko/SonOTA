# -*- mode: python -*-

block_cipher = None

added_files = [
          ('..\static','static'),
          ('..\ssl','ssl') 
         ]

a = Analysis(['..\\sonota.py'],
             pathex=[],
             binaries=[],
             datas = added_files,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
		  a.binaries,
          a.zipfiles,
          a.datas,
          name='sonota',
          debug=True,
          strip=False,
          upx=True,
          console=True,
		  uac_admin=False,
		  icon='..\\res\\wifi.ico' )

