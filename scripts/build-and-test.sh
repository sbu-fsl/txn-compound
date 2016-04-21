#!/bin/bash - 
#=============================================================================
# Build and test TC client.
# 
# by Ming Chen, v.mingchen@gmail.com
#=============================================================================

set -o nounset                          # treat unset variables as an error
set -o errexit                          # stop script if command fail
export PATH="/bin:/usr/bin:/sbin"             
IFS=$' \t\n'                            # reset IFS
unset -f unalias                        # make sure unalias is not a function
\unalias -a                             # unset all aliases
ulimit -H -c 0 --                       # disable core dump
hash -r                                 # clear the command path hash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

ORIGINPWD=$PWD

TC_ROOT="$DIR/../.."

BUILD_TYPE="${1:-Debug}"

echo "using config file at $DIR/../config/tc.ganesha.conf"
cat "$DIR/../config/tc.ganesha.conf"

ps aux | grep ganesha
tail -n 50 /var/log/tcserver.ganesha.log

mkdir $DIR/../tc_client/build
cd $DIR/../tc_client/build
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE ..
make
make install
./MainNFSD/tc_test_write

cd $ORIGINPWD
