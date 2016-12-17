#!/usr/bin/env python

import setuptools

setuptools.setup(name="evtxtract",
      version="0.2",
      description="EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.",
      author="Willi Ballenthin",
      author_email="william.ballenthin@fireeye.com",
      url="https://github.com/williballenthin/evtxtract",
      license="Apache 2.0 License",
      packages=setuptools.find_packages(),
      console_scripts=[
          'evtxtract=evtxtract.main:main',
      ],
      install_requires=[
          'six',
          'lxml',
          'pytest',
          'python-evtx',
      ],
)
