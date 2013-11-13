#!/bin/bash

die () {
    echo "$@"
    echo "exiting"
    exit 1
}

IS_SRC=$(rpm -qp --qf '%{sourcepackage}' --nosignature --nodigest "$1")
[ ".$IS_SRC" = .1 ] || die "Not a source rpm"
NAME=$(rpm -qp --qf '%{name}' --nosignature --nodigest "$1")

WDIR=$(mktemp -d /tmp/srpmrebuild.XXXXXX)
RPMOPTS=(
    --define "_sourcedir $WDIR/sources" 
    --define "_specdir $WDIR/specs" 
    --define "_builddir $WDIR/build"
    --define "_srcrpmdir $WDIR/srpms"
    --define "_rpmdir $WDIR/rpms"
    --define "dist .COSMOS6"
)

rpm "${RPMOPTS[@]}" -iv "$1"
rpmbuild "${RPMOPTS[@]}" -bs "$WDIR/specs/$NAME.spec"


