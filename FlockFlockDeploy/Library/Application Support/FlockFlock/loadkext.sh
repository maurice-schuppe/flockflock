#!/bin/sh
COMMAND=$1

KEXT=/System/Library/Extensions/FlockFlock.kext
if [ -f "$KEXT" ]
then
    echo "KEXT does not exist"
    exit 1
fi

if [ "$COMMAND" = "load" ]
then
    kextload $KEXT
elif [ "$COMMAND" = "unload" ]
then
    kextunload $KEXT
fi
