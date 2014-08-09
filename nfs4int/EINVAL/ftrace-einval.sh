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
  echo '*aio*' >> set_ftrace_filter
  echo '*io_submit*' >> set_ftrace_filter
  echo '*io_getevents*' >> set_ftrace_filter
  echo 'ext4_file_write' >> set_ftrace_filter
  echo 'generic_file_direct_write' >> set_ftrace_filter
  echo 'generic_file_buffered_write' >> set_ftrace_filter
  echo '*direct_IO*' >> set_ftrace_filter
  echo '*do_direct_IO*' >> set_ftrace_filter
  echo '*dio_complete*' >> set_ftrace_filter
  echo '*dio_prep_for_pi*' >> set_ftrace_filter
}


DEBUGFS=`grep debugfs /proc/mounts | awk '{ print $2; }'`

cd $DEBUGFS/tracing

setup_ftrace

echo $$ > set_ftrace_pid

> trace

#dd if=/dev/urandom of=/dev/sdb bs=4k count=1;
#$OLDPWD/dix -p g -wr -s 16 /mnt/hi.txt
rm -f /vfs-ganesha/aaaa
touch /vfs-ganesha/aaaa

echo 1 > tracing_on

/root/nfs/fsl-nfs-ganesha/src/mybuild/FSAL/FSAL_VFS/dixio_test -p w /vfs-ganesha/aaaa

echo 0 > tracing_on

cat trace > /root/trace.txt
