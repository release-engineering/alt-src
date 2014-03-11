#!/bin/bash

rpm -iv --define "_topdir $PWD" "$@"
