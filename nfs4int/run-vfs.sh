#!/bin/bash -
# Launch the secnfs proxy.
#
# This script should be placed in the build directory.
#
#       cp run-secnfs.sh <root-to-nfs-ganesha>/<build-directory>
#
# Usage 1 (executed in the directory):
#
#       cd <root-to-nfs-ganesha>/<build-directory>
#       ./run-secnfs.sh
#
# Usage 2 (executed using full path):
#
#       <root-to-nfs-ganesha>/<build-directory>/run-secnfs.sh

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#PATHPROG=/usr/local/bin/ganesha.nfsd 
PATHPROG=$DIR/MainNFSD/ganesha.nfsd

LOGFILE=/var/log/vfs.ganesha.log
CONFFILE=/etc/ganesha/vfs.ganesha.conf

prog=ganesha.nfsd
PID_FILE=${PID_FILE:=/var/run/${prog}.pid}
LOCK_FILE=${LOCK_FILE:=/var/lock/subsys/${prog}}

$PATHPROG -L $LOGFILE -f $CONFFILE -N NIV_INFO
