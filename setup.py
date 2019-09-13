#!/usr/bin/env python

from setuptools import setup

INSTALL_REQUIRES = ["koji", "rpm", "requests", "PyYAML", "simplejson"]

setup(name='alt-src',
      description='Tool for uploading custom patches to centos source rpm repositories',
      version='1.0',
      url='https://github.com/release-engineering/alt-src.git',
      install_requires=INSTALL_REQUIRES,
      scripts=['alt-src'])
