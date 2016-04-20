# Setup txn-compound on CentOS7
#
# by Garima Gehlot, garima.gehlot@stonybrook.edu
# by Ming Chen, mchen@cs.stonybrook.edu
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
sudo git submodule update --init --recursive
sudo wget http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-6.noarch.rpm
sudo rpm -ivh epel-release-7-6.noarch.rpm

#sudo yum -y update

# clean up the yum cache directory to get rid of
# obsolete headers, if any
#sudo yum clean all

sudo yum install -y cmake
sudo yum install -y glog-devel gflags-devel libgssglue-devel
sudo yum install -y openssl-devel
sudo yum install -y libnfsidmap-devel
sudo yum install -y doxygen
sudo yum install -y gperftools-devel gperftools-libs  # for tcmalloc
sudo yum install -y protobuf-devel leveldb-devel snappy-devel opencv-devel boost-devel hdf5-devel
sudo yum install -y lmdb-devel jemalloc-devel tbb-devel libaio-devel cryptopp-devel
sudo yum -y groupinstall "Development Tools"
sudo yum install -y glibc-headers
sudo yum install -y gcc-c++
sudo yum install -y bison flex
sudo yum install -y libcurl-devel boost-system boost-filesystem boost-regex
sudo yum install -y boost-static
sudo yum install -y glib2-devel glib-devel
sudo yum install -y automake autoconf libtool
sudo yum install -y libcap-devel libwbclient-devel libuuid-devel libblkid-devel

mkdir -p /opt
cd /opt

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
