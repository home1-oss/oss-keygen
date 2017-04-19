#!/usr/bin/env bash

set -e












# if command starts with an option, prepend java
if [ "${1:0:1}" == '-' ]; then
    set -- java ${JAVA_OPTS} -jar *-exec.jar "$@"
fi



exec "$@"
