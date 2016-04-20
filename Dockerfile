FROM centos
MAINTAINER Ming Chen <v.mingchen@gmail.com>
RUN yum install -y git
RUN yum install -y sudo
RUN yum install -y wget
RUN git clone https://github.com/sbu-fsl/txn-compound.git
RUN sh txn-compound/scripts/install-dependency.sh

# build instructions
# mkdir txn-compound/tc_client/debug
# cd txn-compound/tc_client/debug
# cmake -DCMAKE_BUILD_TYPE=Debug ..
# make
# make install
