#!/bin/bash - 
#=============================================================================
# Setup and install nfs-ganesha on Ubuntu
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

sudo apt-get install -y gcc cmake git wget bison flex

cd $HOME
echo "HOME is $HOME"
if [ ! -d nfs-ganesha ]; then
  git clone https://github.com/nfs-ganesha/nfs-ganesha.git
fi
cd nfs-ganesha

# copied from https://github.com/nfs-ganesha/nfs-ganesha/blob/master/.travis.yml
git submodule update --init --recursive
sudo add-apt-repository -y ppa:gluster/glusterfs-3.6
wget -q -O- 'https://ceph.com/git/?p=ceph.git;a=blob_plain;f=keys/release.asc' | sudo apt-key add -
echo deb http://eu.ceph.com/debian-firefly/ $(lsb_release -sc) main | sudo tee /etc/apt/sources.list.d/ceph.list
sudo apt-add-repository -y ppa:lttng/ppa
sudo apt-get update -q
sudo apt-get install -y libnfsidmap2
sudo apt-get install -y libnfsidmap-dev
sudo apt-get install -y libkrb5-3
sudo apt-get install -y libkrb5-dev
sudo apt-get install -y libk5crypto3
sudo apt-get install -y libgssapi-krb5-2
sudo apt-get install -y libgssglue1
sudo apt-get install -y libdbus-1-3
sudo apt-get install -y libattr1-dev
sudo apt-get install -y libacl1-dev
sudo apt-get install -y dbus
sudo apt-get install -y libdbus-1-dev
sudo apt-get install -y libcap-dev
sudo apt-get install -y libjemalloc-dev
sudo apt-get install -y glusterfs-common
sudo apt-get install -y uuid-dev
sudo apt-get install -y libblkid-dev
sudo apt-get install -y xfslibs-dev
sudo apt-get install -y libcephfs-dev
sudo apt-get install -y libwbclient-dev
sudo apt-get install -y lttng-tools
sudo apt-get install -y liblttng-ust-dev
sudo apt-get install -y lttng-modules-dkms
sudo apt-get install -y pyqt4-dev-tools
sudo apt-get install -y rpm2cpio
sudo apt-get install -y libaio-dev
sudo apt-get install -y libibverbs-dev
sudo apt-get install -y librdmacm-dev
sudo apt-get install -y doxygen

mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=debug ../src/ && make
