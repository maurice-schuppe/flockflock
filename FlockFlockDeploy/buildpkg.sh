#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo; echo "Script $0 must be run as root"; echo
   exit 1
fi

VERSION=$1
pkgbuild --root `pwd`/Library --scripts pkgbuild-scripts --identifier com.zdziarski.FlockFlock --version $VERSION --ownership recommended --install-location /Library FlockFlock.pkg

codesign -fs "Mac Developer: Jonathan Zdziarski" FlockFlock.pkg 
