#!/bin/bash

explode () {
    # explode a single srpm
    is_src=$(rpm --nosignature --nodigest --qf '%{sourcepackage}' -qp "$1")
    if [ ".$is_src" != ".1" ]
    then
        echo "Not a source package: $1"
        return
    fi
    nvr=$(rpm --nosignature --nodigest --qf '%{n}-%{v}-%{r}' -qp "$1")
    if [ -h "$nvr" ]
    then
        echo "$nvr is a symlink"
        return
    elif [ -d "$nvr" ]
    then
        echo "$nvr directory exists"
        return
    elif [ -e "$nvr" ]
    then
        echo "$nvr exists"
        return
    fi
    dir="$PWD/$nvr"
    mkdir "$dir"

    rpm --nosignature -iv --define "_topdir $dir" "$1"
}

for fn in "$@"
do
    explode "$fn"
done

#TODO - handle .X.metadata and .gitignore
#see https://nazar.karan.org/blob/nazar-repos/HEAD/sync_sources.sh

#TODO - integrate with pyrpkg


