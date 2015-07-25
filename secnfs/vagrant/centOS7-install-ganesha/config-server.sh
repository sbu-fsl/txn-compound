# Checkout the nfs-ganesha --integrity-2.1 branch
# Download kernel 3.14.17, apply patches, compile and install
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
sudo yum install -y gcc cmake git libtool wget bison flex bc patch

# parse command line argument for username
USR="";

usage()
{
        echo "**Error: Please use '-u' option to pass the username for the git respository"
        echo "e.g. ./config-server -u <username>"
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

HOME_DIR=`pwd`;


# checkout the integrity-2.1 branch git repository
mkdir ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/known_hosts
ssh-keyscan -H git.fsl.cs.sunysb.edu >> ~/.ssh/known_hosts
git_repo="$USR@git.fsl.cs.sunysb.edu:/scm/fslgit/fsl-nfs-ganesha.git";
if [ ! -d fsl-nfs-ganesha ]; then
	git clone -b integrity-2.1 $git_repo;
fi

# checkout the master repository
sudo mkdir master_repo
cd master_repo
if [ ! -d fsl-nfs-ganesha ]; then
	git clone $git_repo;
fi

# Download the kernel
cd /usr/src/
wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.14.17.tar.xz
tar -xvf linux-3.14.17.tar.xz
cd linux-3.14.17

# Apply patches
for i in $HOME_DIR/fsl-nfs-ganesha/nfs4int/pi-patchset-v2/?-*.patch;
	do
		if [[ $i != *"0-userspace"* ]]; then
		sudo patch -p1 < $i;
		fi
	done

# Apply fixes
for i in $HOME_DIR/fsl-nfs-ganesha/nfs4int/pi-patchset-v2/000?-fix*.patch;
	do
		sudo patch -p1 < $i;
	done

# Configure the kernel
sudo make olddefconfig

# Compile the kernel
sudo make

# Compile the kernel modules
sudo make modules

# Install the kernel modules
sudo make modules_install

# Install the new kernel
sudo make install

# make the new kernel default
sudo sed -i.bak 's/^\(GRUB_DEFAULT=\).*/\10/' /etc/default/grub
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# reboot the machine
sudo reboot

