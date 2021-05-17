#!/usr/bin/env python

from setuptools import setup, find_packages


def get_description():
    return "Tool for uploading custom patches to centos source rpm repositories"


def get_requirements():
    with open("requirements.txt") as f:
        return f.read().splitlines()


def get_long_description():
    with open("README.md") as f:
        text = f.read()

    # Long description is everything after README's initial heading
    idx = text.find("\n\n")
    return text[idx:]


setup(
      name="alt-src",
      version="1.6.1",
      packages=find_packages(exclude=["tests"]),
      url="https://github.com/release-engineering/alt-src",
      license="GNU General Public License",
      description=get_description(),
      long_description=get_long_description(),
      long_description_content_type="text/markdown",
      classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 2.4",
            "Programming Language :: Python :: 2.6",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
      ],
      install_requires=get_requirements(),
      entry_points={
            "console_scripts": [
                  "alt-src = alt_src:entry_point",
            ],
      },
      project_urls={
        "Changelog": "https://github.com/release-engineering/alt-src/blob/master/CHANGELOG.md",
    },
)
