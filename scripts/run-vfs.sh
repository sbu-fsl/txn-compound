#!/bin/bash -
# Launch the NFS server running VFS FSAL
#
# This script should be placed in the build directory.
#
#       cp run-vfs.sh <root-to-nfs-ganesha>/<build-directory>
#
# Usage:
#
#       cd <root-to-nfs-ganesha>/<build-directory>
#       ./run-vfs.sh [debug|release]

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

running_mode="${1:-release}"

if [[ ${running_mode} == 'debug' ]]; then
  CONFFILE=/etc/ganesha/vfs.ganesha.conf
  LOGLEVEL=DEBUG
elif [[ ${running_mode} == 'release' ]]; then
  CONFFILE=/etc/ganesha/vfs.release.ganesha.conf
  LOGLEVEL=EVENT
else
  echo "usage: $0 [debug|release]"
  exit 1
fi

PATHPROG=$DIR/MainNFSD/ganesha.nfsd

LOGFILE=/var/log/vfs.ganesha.log

prog=ganesha.nfsd
PID_FILE=${PID_FILE:=/var/run/${prog}.pid}
LOCK_FILE=${LOCK_FILE:=/var/lock/subsys/${prog}}

$PATHPROG -L ${LOGFILE} -f ${CONFFILE} -N ${LOGLEVEL}
