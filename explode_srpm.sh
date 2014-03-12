#!/bin/bash

rpm -iv --define "_topdir $PWD" "$@"

#TODO - handle .X.metadata and .gitignore
#see https://nazar.karan.org/blob/nazar-repos/HEAD/sync_sources.sh

#TODO - integrate with pyrpkg


