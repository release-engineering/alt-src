#!/usr/bin/env python

from setuptools import setup, find_packages


def get_description():
    return "Tool for uploading custom patches to centos source rpm repositories"


setup(
      name="alt-src",
      version="1.0",
      packages=find_packages(exclude=["tests"]),
      url="https://github.com/release-engineering/alt-src",
      license="GNU General Public License",
      description=get_description(),
      classifiers=[
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 2.4"
            "Programming Language :: Python :: 2.6",
            "Programming Language :: Python :: 2.7",
            "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
      ],
      install_requires=["koji", "rpm", "requests", "PyYAML", "simplejson"],
      entry_points={
            "console_scripts": [
                  "alt-src = alt_src:entry_point",
            ],
      },
)
