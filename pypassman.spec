# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['C:\\codebase\\pypassman\\__main__.py'],
             pathex=['C:\\codebase\\pypassman'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=['alabaster', 'PyQt5', 'notebook', 'markupsafe', 'matplotlib', 'lib2to3', 'tcl', 'tk', 'zmq', 'tornado', 'sphinx', 'sqlalchemy', 'socket', 'multiprocessing', 'queue', 'sqlite3', 'ssl', 'scipy', 'jedi', 'IPython', 'email', 'email.message', 'email.utils', 'openpyxl', 'smtplib', 'urllib', 'http.client', 'pydoc', 'mkl_fft', 'Cython', 'jinja2', 'http.server', 'setuptools', 'setuptools.package_index', 'setuptools.ssl_support', 'socketserver', 'distutils.dist', 'distutils.config', 'html5lib', 'lzma', 'importlib_metadata', 'importlib_metadata._compat', 'pkg_resources', 'xmlrpc.server', 'xmlrpc.client', 'sysconfig', 'logging.handlers', 'logging.config', 'pyreadline.logger', 'concurrent.futures.process', 'concurrent.futures.thread', 'cgi'],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='pypassman',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True , resources=['C:\\\\codebase\\\\pypassman\\\\*.json:.'])
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='pypassman')
