#!/bin/bash
# XXX: add some metadata to the .<pn>.metadata file, make it the readme file
# add details as 'non -text sources, with a url to the file
# this works, good enough, (c) Karanbir Singh June 2009

HomeDir=/home/kbsingh/git
VCSDir=${HomeDir}/git
BINDir=${HomeDir}/sources
DoneDir=${HomeDir}/done/

function import_srpm {
  f=$1 
  dver=$2
  cd $VCSDir
  pn=$(rpm --qf "%{name}\n" -qp $f)
  pd=$(rpm --qf "%{buildtime}\n" -qp $f)
  pdesc=$(rpm --qf "%{summary}\n" -qp $f)
  if [  ! -e ${VCSDir}/${pn}/ ]; then
    mkdir -p ${VCSDir}/${pn}
    cd ${VCSDir}/${pn}

    git init
    echo 'The master branch has no content' > README.md
    echo ' ' >> README.md
    echo 'Look at the c6 branch if you are working with CentOS-6, or the c4 / c5 branch for CentOS-4 or CentOS-5' >> README.md
    echo ' ' >> README.md
    echo 'If you find this file in a distro specific branch, it means that no content has been checked in yet' >> README.md

    git add README.md && git commit -m "init git for ${pn} " README.md
    for rver in c4 c5 c6 c5-plus c6-plus c7; do
      git branch ${rver}
      mkdir -p ${BINDir}/${pn}/${rver}
    done
    ssh reimzul@nazar.karan.org "mkdir -p /srv/git/distro/${pn}.git && cd /srv/git/distro/${pn}.git && git --bare init"
    cat ${HomeDir}/blit.config | sed -e "s/T_DESC/${pdesc}/g" | ssh reimzul@nazar.karan.org "cat >> /srv/git/distro/${pn}.git/config"
    git remote add origin reimzul@nazar.karan.org:/srv/git/distro/${pn}
    git push --all origin
  fi
  cd ${VCSDir}/${pn}
  # we need to change the user we loging to nazar with
  sed -i 's/git@nazar/reimzul@nazar/g' .git/config
  if [ `git branch | grep ${dver} | wc -l` -lt 1 ]; then
    git checkout master
    git branch ${dver}
    mkdir -p ${BINDir}/${pn}/${rver}
    git push --all origin
  fi
  git checkout ${dver}
  git pull origin ${dver}
  if [ $? -eq 0 ]; then
    rm -rf *
    rm .${pn}.metadata

    sudo /bin/date -s @${pd}
    rpm --define "_topdir `pwd`" -ivh $Hdir/$f
    git add SPECS/
    for y in `find SOURCES/ -maxdepth 1 -type f -exec file {} \; |  egrep '.*:.*text' | cut -d ":" -f1`; do
      git add $y
    done
    for x in `find SOURCES/ -maxdepth 1 -type f -exec file {} \; | egrep -v '.*:.*text' | cut -d ":" -f1`; do
      bin_sum=$(sha1sum $x)
      echo $bin_sum  >> .${pn}.metadata
      fsum=$(echo $bin_sum | cut -f1 -d\ )
      fnam=$(echo $bin_sum | cut -f2 -d\ )
      mv $fnam ${BINDir}/${pn}/${dver}/${fsum}
    done
    git add .${pn}.metadata
    git commit -m "import `basename ${f}`" -a
    date > $DoneDir/$dver/$srpm
    git push --all origin

    rsync -PHvr ${BINDir}/${pn} sources@nazar.karan.org:/srv/sources/
  else
    echo 'fail ' $dver $srpm | mail -s 'Import fail' kbsingh@karan.org
  fi
}

mkdir -p $VCSDir
mkdir -p $BINDir
mkdir -p $DoneDir $DoneDir/c4 $DoneDir/c5 $DoneDir/c6 $DoneDir/c5-plus $DoneDir/c6-plus $DoneDir/c7

cd ${HomeDir}/processing/
# make sure all the files have the correct timestamp + check clock sanity
sudo /usr/sbin/ntpdate clock.redhat.com
find . -type f -name \*.src.rpm -exec ~/bin/rpm_fix_filetime.sh {} \;
for x in `find . -name *.src.rpm -printf "%TY%Tm%Td%TH%TM %p\n" | sort -n | cut -f2 -d\ `; do 
  dver=$(echo $x | cut -f2 -d'/')
  srpm=$(echo $x | cut -f3 -d'/')
  if [ ! -e ${DoneDir}/${dver}/${srpm} ]; then
    import_srpm ${HomeDir}/processing/${dver}/${srpm} ${dver}    
  fi
  mkdir -p ${HomeDir}/processing.done/${dver}/
  mv ${HomeDir}/processing/${dver}/${srpm} ${HomeDir}/processing.done/${dver}/
done

sudo /usr/sbin/ntpdate clock.redhat.com
