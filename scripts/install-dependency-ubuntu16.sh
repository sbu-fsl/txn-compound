#!/bin/bash -
#
# Setup txn-compound on Ubuntu 16
#
# by Farhaan Jalia, farhaan.jalia@stonybrook.edu
#=============================================================================

set -o nounset                          # treat unset variables as an error
set -o errexit                          # stop script if command fail
export PATH="/bin:/usr/bin:/sbin:/usr/local/bin"
IFS=$' \t\n'                            # reset IFS
unset -f unalias                        # make sure unalias is not a function
\unalias -a                             # unset all aliases
ulimit -H -c 0 --                       # disable core dump
hash -r                                 # clear the command path hash

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# got to the root of this git repo
cd $DIR/../

# NFS-ganesha specific
git submodule update --init --recursive
#wget http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-6.noarch.rpm
#rpm -ivh epel-release-7-6.noarch.rpm

#sudo yum -y update

# clean up the yum cache directory to get rid of
# obsolete headers, if any
#sudo yum clean all

sudo apt-get install -y cmake
sudo apt-get install -y libgoogle-glog-dev libgflags-dev libgssglue-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y libnfsidmap-dev
sudo apt-get install -y doxygen
sudo apt-get install -y google-perftools
sudo apt-get install -y libgoogle-perftools-dev libgoogle-perftools4  # for tcmalloc
sudo apt-get install -y libsnappy-dev
sudo apt-get install -y libopencv-dev
sudo apt-get install -y libboost-dev
sudo apt-get install -y libhdf5-dev
#yum install -y protobuf-devel leveldb-devel
sudo apt-get install -y liblmdb-dev
sudo apt-get install -y libjemalloc-dev
sudo apt-get install -y libtbb-dev
sudo apt-get install -y libaio-dev
sudo apt-get install -y libcrypto++-dev
sudo apt-get install -y build-essential
##yum install -y glibc-headers
#yum install -y gcc-c++
sudo apt-get install -y bison flex
sudo apt-get install -y libcurl4-gnutls-dev
sudo apt-get install -y libcurl4-openssl-dev
sudo apt-get install -y libboost-system-dev
sudo apt-get install -y libboost-regex-dev
sudo apt-get install -y libboost-filesystem-dev
#yum install -y boost-static
#yum install -y glib2-devel glib-devel
sudo apt-get install -y automake autoconf libtool
sudo apt-get install -y libcap-dev
sudo apt-get install -y libwbclient-dev
sudo apt-get install -y uuid-dev
sudo apt-get install -y libblkid-dev
sudo apt-get install -y libkrb5-dev
sudo apt-get install -y libgss-dev

# To resolve https://github.com/nfs-ganesha/nfs-ganesha/issues/67
#yum install -y libtirpc

mkdir -p /opt
cd /opt

# This will install gflags and put the cmake rule file at
# /usr/local/lib/cmake/gflags/gflags-config.cmake
if [ ! -d gflags ]; then
  git clone https://github.com/gflags/gflags.git
  cd gflags
  mkdir build
  cd build
  cmake -DCMAKE_BUILD_TYPE=Release ../src/
  make
  sudo make install
fi

# setup gmock and gtest
if [ ! -d gmock-1.7.0 ]; then
  wget https://github.com/google/googlemock/archive/release-1.7.0.zip
  unzip release-1.7.0.zip
  mv googlemock-release-1.7.0 gmock-1.7.0

  cd gmock-1.7.0
  wget https://github.com/google/googletest/archive/release-1.7.0.zip
  unzip release-1.7.0.zip
  mv googletest-release-1.7.0 gtest

  autoreconf -fvi
  ./configure
  make
fi

echo "GOOGLE_MOCK is installed at /opt/gmock-1.7.0"
echo "GOOGLE_TEST is installed at /opt/gmock-1.7.0/gtest"
