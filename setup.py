#!/usr/bin/env python

from distutils.core import setup

setup(name='redissentry-core',
      version='0.1.1',
      description='Module protecting a web framework against password bruteforce attacks',
      author='Lev Maximov',
      author_email='lev.maximov@gmail.com',
      url='http://github.com/axil/redissentry-core',
      packages=['redissentrycore'],
      install_requires=['redis'],
      license='MIT',
      classifiers = [
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Internet :: WWW/HTTP',
          'Topic :: Security',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: Software Development :: User Interfaces',
      ],
)
