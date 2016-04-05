#!/bin/bash -
# Launch the NFS proxy.
#
# This script should be placed in the build directory.
#
#       cp run-proxy.sh <root-to-nfs-ganesha>/<build-directory>
#
# Usage 1 (executed in the directory):
#
#       cd <root-to-nfs-ganesha>/<build-directory>
#       ./run-proxy.sh
#
# Usage 2 (executed using full path):
#
#       <root-to-nfs-ganesha>/<build-directory>/run-proxy.sh

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

PATHPROG=MainNFSD/ganesha.nfsd

LOGFILE=/var/log/proxy.ganesha.log
CONFFILE=/etc/ganesha/crypt-proxy.ganesha.conf

prog=ganesha.nfsd
PID_FILE=${PID_FILE:=/var/run/${prog}.pid}
LOCK_FILE=${LOCK_FILE:=/var/lock/subsys/${prog}}

$PATHPROG -L $LOGFILE -f $CONFFILE -N NIV_DEBUG
