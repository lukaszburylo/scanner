from distutils.core import setup

setup(name='Scanner',
      version='1.0',
      description='Scan network nad IPs',
      author='Lukasz Burylo',
      author_email='lukasz@burylo.com',
      packages=['distutils', 'distutils.command'],
      url='https://github.com/lukaszburylo/scanner',
      py_modules=['ipscanner','scanner']
     )



