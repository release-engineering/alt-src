Alt-src
=======

Alt-src is a tool for pushing SRPM metadata into a git repo.

[![PyPI version](https://badge.fury.io/py/alt-src.svg)](https://badge.fury.io/py/alt-src)
[![Build Status](https://travis-ci.org/release-engineering/alt-src.svg?branch=master)](https://travis-ci.org/release-engineering/alt-src)
[![Coverage Status](https://coveralls.io/repos/github/release-engineering/alt-src/badge.svg?branch=master)](https://coveralls.io/github/release-engineering/alt-src?branch=master)

Alt-src takes source RPMs as input, unpacks packaging metadata such as .spec files and
patch files, and pushes them into a git repository. It's most notably used to populate
[CentOS git](https://git.centos.org).

Usage
-----

    alt-src --push <branch> <package.src.rpm>

This command will check out the git repo for the given package and branch, unpack the
input RPM and create/push a new commit using the unpacked sources.
A tag is also created under `imports/<branch>/<nvr>`.

If a repo doesn't exist for the given package, the command will create one using
the Pagure API.

The command accepts these inputs:

* `<package-filename.src.rpm>` - path to a local SRPM file
* `--koji <build-nvr>` - SRPM is pulled from configured koji instance
* `--koji <build-nvr>:module.src.txt` - instead of SRPM, modulemd is imported

If enabled, the command also sends notifications to the configured email address.

License
-------

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
