#!/bin/bash - 
#=============================================================================
# Run ftrace
# 
# by Ming Chen, v.mingchen@gmail.com
#=============================================================================

set -o nounset                          # treat unset variables as an error
#set -o errexit                          # stop script if command fail
export PATH="/bin:/usr/bin:/sbin"             
IFS=$' \t\n'                            # reset IFS
unset -f unalias                        # make sure unalias is not a function
\unalias -a                             # unset all aliases
ulimit -H -c 0 --                       # disable core dump
hash -r                                 # clear the command path hash

function setup_ftrace() {
  echo 'function_graph' > current_tracer
  echo 'bio_*' > set_ftrace_filter
  echo 'sd_dif_*' >> set_ftrace_filter
  echo 'blk_*' >> set_ftrace_filter
  echo '*block*' >> set_ftrace_filter
}


DEBUGFS=`grep debugfs /proc/mounts | awk '{ print $2; }'`

cd $DEBUGFS/tracing

#setup_ftrace

echo $$ > set_ftrace_pid

> trace

echo 1 > tracing_on

#dd if=/dev/urandom of=/dev/sdb bs=4k count=1;
$OLDPWD/dix -p g -wr -s 16 /mnt/hi.txt

echo 0 > tracing_on

cat trace > $OLDPWD/trace.txt
