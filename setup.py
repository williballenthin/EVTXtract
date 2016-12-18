#!/usr/bin/env python

import os
import setuptools


# this sets __version__
# # via: http://stackoverflow.com/a/7071358/87207
# # and: http://stackoverflow.com/a/2073599/87207
with open(os.path.join("evtxtract", "version.py"), "rb") as f:
     exec(f.read())

setuptools.setup(name="evtxtract",
      version=__version__,
      description="EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.",
      author="Willi Ballenthin",
      author_email="william.ballenthin@fireeye.com",
      url="https://github.com/williballenthin/evtxtract",
      license="Apache 2.0 License",
      packages=setuptools.find_packages(),
      entry_points={
          "console_scripts": [
              "evtxtract=evtxtract.main:main",
          ]
      },
      install_requires=[
          'six',
          'lxml',
          'pytest',
          'python-evtx>=0.5.2',
      ],
)
