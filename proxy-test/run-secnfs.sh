#PATHPROG=/usr/local/bin/ganesha.nfsd 
PATHPROG=MainNFSD/ganesha.nfsd

LOGFILE=/var/log/secnfs.ganesha.log
CONFFILE=/etc/ganesha/secnfs.ganesha.conf

prog=ganesha.nfsd
PID_FILE=${PID_FILE:=/var/run/${prog}.pid}
LOCK_FILE=${LOCK_FILE:=/var/lock/subsys/${prog}}

$PATHPROG -L $LOGFILE -f $CONFFILE -N NIV_INFO
