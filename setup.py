import PyInstaller.__main__ as main
import os

def cur_dir():
  return os.path.dirname(os.path.realpath(__file__))


import pandas.io.common
if __name__ == "__main__":

  main.run([
    '--name=%s'% 'pypassman',
    # '--onefile',
    '--resource=%s' % os.path.join(cur_dir(), "*.json:."),
    '--exclude-module=alabaster',
    '--exclude-module=PyQt5',
    '--exclude-module=notebook',
    '--exclude-module=markupsafe',
    '--exclude-module=matplotlib',
    '--exclude-module=lib2to3',
    '--exclude-module=tcl',
    '--exclude-module=tk',
    '--exclude-module=zmq',
    '--exclude-module=tornado',
    '--exclude-module=sphinx',
    '--exclude-module=sqlalchemy',
    '--exclude-module=socket',
    '--exclude-module=multiprocessing',
    '--exclude-module=queue',
    '--exclude-module=sqlite3',
    '--exclude-module=ssl',
    '--exclude-module=scipy',
    '--exclude-module=jedi',
    '--exclude-module=IPython',
    '--exclude-module=email',
    '--exclude-module=email.message',
    '--exclude-module=email.utils',
    '--exclude-module=openpyxl',
    '--exclude-module=smtplib',
    '--exclude-module=urllib',
    '--exclude-module=http.client',
    '--exclude-module=pydoc',
    '--exclude-module=mkl_fft',
    '--exclude-module=Cython',    
    '--exclude-module=jinja2',  
    '--exclude-module=http.server',
    '--exclude-module=setuptools',
    '--exclude-module=setuptools.package_index',
    '--exclude-module=setuptools.ssl_support',
    '--exclude-module=socketserver',
    '--exclude-module=distutils.dist',
    '--exclude-module=distutils.config',
    '--exclude-module=html5lib',
    '--exclude-module=lzma',
    
    '--exclude-module=importlib_metadata',
    '--exclude-module=importlib_metadata._compat',
    '--exclude-module=pkg_resources',
    '--exclude-module=xmlrpc.server',
    '--exclude-module=xmlrpc.client',
    '--exclude-module=sysconfig',
    '--exclude-module=logging.handlers',
    '--exclude-module=logging.config',
    '--exclude-module=pyreadline.logger',
    '--exclude-module=concurrent.futures.process',
    '--exclude-module=concurrent.futures.thread',
    '--exclude-module=cgi',
    
    os.path.join(cur_dir(), '__main__.py')
  ])