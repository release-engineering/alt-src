Alt src
=======

Alt-src is tool used to push patches in provided srpms into centos git.

[![Build Status](https://travis-ci.org/release-engineering/alt-src.svg?branch=master)](https://travis-ci.org/release-engineering/alt-src)
[![Coverage Status](https://coveralls.io/repos/github/release-engineering/alt-src/badge.svg?branch=master)](https://coveralls.io/github/release-engineering/alt-src?branch=master)

Example
-------

alt-src --push <branch> <package.src.rpm>

Script checkouts centos repository for the package on specified branch. Input rpm is then
unpacked and all sources specified in spec file are staged to copy of git repository.
If there are new sources, new commit is created and pushed with tag to centos git.

It's possible to use following type of inputs
local-package <package-filename.src.rpm>
--koji <package-nvr> - package srpm is pulled from configured koji instance
--koji <nvr>:module.src.txt - instead of srpm, modulemd is imported

If enabled, script also sends notification of result to configured email address
