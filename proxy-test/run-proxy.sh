#PATHPROG=/usr/local/bin/ganesha.nfsd 
PATHPROG=MainNFSD/ganesha.nfsd

LOGFILE=/var/log/proxy.ganesha.log
CONFFILE=/etc/ganesha/proxy.ganesha.nfsd.conf

prog=ganesha.nfsd
PID_FILE=${PID_FILE:=/var/run/${prog}.pid}
LOCK_FILE=${LOCK_FILE:=/var/lock/subsys/${prog}}

$PATHPROG -L $LOGFILE -f $CONFFILE -N NIV_DEBUG
