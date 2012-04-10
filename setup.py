#!/usr/bin/env python

from distutils.core import setup

setup(name='redissentry',
      version='0.1.0',
      description='Module protecting a web framework against password bruteforce attacks',
      author='Lev Maximov',
      author_email='lev.maximov@gmail.com',
      url='http://github.com/axil/redissentry',
      packages=['redissentry'],
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
