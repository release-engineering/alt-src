#!/usr/bin/env python

from setuptools import setup, find_packages


def get_description():
    return "Tool for uploading custom patches to centos source rpm repositories"


def get_requirements():
    with open("requirements.txt") as f:
        return f.read().splitlines()


setup(
      name="alt-src",
      version="0.2.0",
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
      install_requires=get_requirements(),
      python_requires="<=2.7",
      entry_points={
            "console_scripts": [
                  "alt-src = alt_src:entry_point",
            ],
      },
)
