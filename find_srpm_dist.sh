#!/bin/bash

fn=$1

dir=$(mktemp -d /tmp/temp-work.XXXXXX)
cd $dir || exit 1

nvr=$(rpm --nosignature --nodigest -qp "$fn" --qf '%{n}-%{v}-%{r}')
name=$(rpm --nosignature --nodigest -qp "$fn" --qf '%{n}')

rpm -iv --nosignature --nodigest --define "_topdir $dir" "$fn" &>/dev/null

#now remake srpm with custom dist

mydist="XXXjsdf9ur7qlkasdh4gygXXX"
nvr2=$(rpm --define "dist $mydist" -q --specfile "$dir/SPECS/$name.spec" --qf '%{n}-%{v}-%{r}\n' 2>/dev/null | head -n 1)

#echo $nvr2

head=${nvr2%$mydist*}

if [ ".$head" = ".$nvr2" ]
then
    #no dist tag
    echo "NONE $nvr"
    exit
fi

tail=${nvr2#*$mydist}

frag=${nvr#$head}
dist=${frag%$tail}

echo "$dist $nvr"
