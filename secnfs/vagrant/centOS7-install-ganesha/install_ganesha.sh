# Setup and install nfs-ganesha on CentOS7
#
# by Garima Gehlot, garima.gehlot@stonybrook.edu
#=============================================================================

set -o nounset                          # treat unset variables as an error
set -o errexit                          # stop script if command fail
export PATH="/bin:/usr/bin:/sbin:/usr/local/bin"
IFS=$' \t\n'                            # reset IFS
unset -f unalias                        # make sure unalias is not a function
\unalias -a                             # unset all aliases
ulimit -H -c 0 --                       # disable core dump
hash -r                                 # clear the command path hash

# common libraries required
#sudo yum install -y gcc cmake git libtool wget bison flex

# parse command line argument for username
USR="";

usage()
{
        echo "**Error: Please use '-u' option to pass the username for the git respository"
        echo "e.g. ./install_ganesha -u <username>"
        exit 1;
}

while getopts :u: opt; do
  case $opt in
    u)
      if [[ $OPTARG = -* ]]; then
        ((OPTIND--))
        continue
      fi

      USR=$OPTARG ;;

    \?)
      usage;;
  esac
done

if [ $OPTIND -eq 1 ]; then
        usage
fi


# checkout the git repository
sudo ssh-keygen -R git.fsl.cs.sunysb.edu
sudo ssh-keyscan -H git.fsl.cs.sunysb.edu >> ~/.ssh/known_hosts
git_repo="$USR@git.fsl.cs.sunysb.edu:/scm/fslgit/fsl-nfs-ganesha.git";
if [ ! -d fsl-nfs-ganesha ]; then
  git clone -b sec_vs_cache $git_repo;
fi

cd fsl-nfs-ganesha

# NFS-ganesha specific
#git submodule update --init --recursive
sudo wget -P /etc/yum.repos.d http://download.gluster.org/pub/gluster/glusterfs/LATEST/RHEL/glusterfs-epel.repo
sudo rpm --import 'https://ceph.com/git/?p=ceph.git;a=blob_plain;f=keys/release.asc'
#su -c 'rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm'
#sudo yum install -y snappy leveldb gdisk gperftools-libs
#su -c 'rpm -Uvh http://ceph.com/rpm-dumpling/el6/noarch/ceph-release-1-0.el6.noarch.rpm'
#su -c 'rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm'
#sudo yum -y update

cd ..

# clean up the yum cache directory to get rid of
# obsolete headers, if any
sudo yum clean all

#sudo yum install -y glog-devel gflags-devel libgssglue-devel
#sudo yum install -y openssl-devel
#sudo yum install -y libnfsidmap-devel
#sudo yum install -y doxygen
#sudo yum install -y protobuf-devel leveldb-devel snappy-devel opencv-devel boost-devel hdf5-devel
#sudo yum install -y lmdb-devel jemalloc-devel tbb-devel libaio-devel cryptopp-devel
#sudo yum -y groupinstall "Development Tools"
#sudo yum install -y glibc-headers
#sudo yum install -y gcc-c++
#sudo yum install -y libcurl-devel

# set the environment variables required for configuration
# and add it to the .bashrc file as well
echo "export GOOGLE_TEST=$PWD/gtest-1.7.0" >> ~/.bashrc
echo "export GOOGLE_MOCK=$PWD/gmock-1.7.0" >> ~/.bashrc
export GOOGLE_TEST=$PWD/gtest-1.7.0
export GOOGLE_MOCK=$PWD/gmock-1.7.0

# setup gtest
if [ ! -d gtest-1.7.0 ]; then
        wget http://googletest.googlecode.com/files/gtest-1.7.0.zip;
        unzip gtest-1.7.0.zip;
        cd gtest-1.7.0;
        /bin/sh configure;
        make;
        cd -;
        rm -f gtest-1.7.0.zip;
fi

# setup gmock
if [ ! -d gmock-1.7.0 ]; then
        wget http://googlemock.googlecode.com/files/gmock-1.7.0.zip;
        unzip gmock-1.7.0.zip;
        cd gmock-1.7.0;
        libtoolize --copy;
        autoconf;
        autoheader;
        /bin/sh configure;
        make;
        cd -;
        rm -f gmock-1.7.0.zip;
fi

# create build directory
cd fsl-nfs-ganesha
sudo mkdir -p build

# Install Clamav
echo "Running Clamav install script"
cd ./secnfs/clamav/
#yes | /bin/sh install_clamav.sh
cd -
echo "Finished installing Clamav"

# configure and install NFS ganesha
cd build && sudo -E cmake -DCMAKE_BUILD_TYPE=Debug ../src/ && sudo make && sudo make install

