import PyInstaller.__main__ as main
import os

def cur_dir():
  return os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__":

  main.run([
    '--name=%s'% 'pypassman',
    '--onefile',
    '--resource=%s' % os.path.join(cur_dir(), "*.json"),
    os.path.join(cur_dir(), '__main__.py')
  ])