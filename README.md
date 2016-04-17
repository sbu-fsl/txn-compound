About
=====
This "txn-compound" project is short for "transactional compound".  The goal of
this project is to achieve greater performance by leveraging NFSv4's compound
procedures, which is currently under-utilized as we found in our SIGMETRICS'15
paper "Newer Is Sometimes Better: An Evaluation of NFSv4.1". Available at
https://www.fsl.cs.sunysb.edu/docs/nfs4perf/nfs4perf-sigm15.pdf

In a nutshell, the biggest reason why compound procedures are practically
ineffective is the lower-level nature of POSIX file-system API.  Therefore, in
this project, we will supplement POSIX with higher-level APIs that can take
full advantage of compound procedures.  Changing or adding APIs are always a
scary thing, but having the choice for something different is always better
than "no choice."

The project will be implemented as a user-space file-system library with the
API defined in [tc_client/include/tc_api.h](tc_client/include/tc_api.h).  Right
now, we are implementing two implementations of the API: TC_NFS4 and TC_POSIX.
The TC_NFS4 will implement the API using NFS4's compound procedures whenever
possible, whereas TC_POSIX just translates the higher-level functions to
lower-level POSIX functions.

In theory, transactional compounds can be initiated by applications in storage
client, then be transfered/translated all the way down (through network, OS, and
the deep storage stack) to hardware, such as a Fusion-IO device with internal
transactional support.  Although, the project currently focus on only the
client and API part of transactional compounds, in the future, we would like to
push txn-compound all the way down to the right place, no matter it is the
NFS-Server, the in-kernel file-system, or the storage devices.

Get Started
===========
Note: Currently, the project has only been tested under Linux, or more
specifically, CentOS 7.

Prerequisite
------------
To compile and run the projects, you need CMake, G++, Jemalloc, Google Test,
Google Mock, ........................... Life will be so much better if we
have a package manager like Maven in the C/C++ world :-(

So, the simplest way is to create a CentOS VM, and then execute
[`scripts/install-dependency.sh`](scripts/install-dependency.sh)

Build
-----

        cd tc_client
        mkdir debug
        cd debug
        sudo -E cmake -DCMAKE_BUILD_TYPE=Debug ../src
        make

Install
-------
Assuming staying in the debug directory created above:

        sudo make install && sudo make install_manifest.txt

Configure
---------
All configurations are done by editing the config file at
"txn-compound/config/tc.ganesha.conf".

1. start an NFS server (e.g., NFS-Ganesha), and update its IP in the config
   file.

2. configure the NFS server to export a directory called "/vfs0", or update the
   exported directory (default to "/vfs0") accordingly in the config file.

3. create the test file in the exported directory, or update the test file path
   to an existing file in <txn-compound>/tc_client/MainNFSD/tc_test_read.c

        mkdir -p /vfs0/tcdir
        echo "hello txn-compound" > /vfs0/tcdir/abcd

Run
---
Please check "dmesg" and the log file at "/tmp/tc_test_read.log":

        cd  debug/MainNFSD
        sudo ./tc_test_read


Code tree
=========

NFS-Ganesha
-----------
The source code of txn-compound is largely adapted from NFS-Ganesha,
particularly PROXY_FSAL.  So this repository contains many files from
NFS-Ganesha that are not really needed here; they will be gradually cleaned up
in the future.

NFS-Ganesha is an NFSv3,v4,v4.1 fileserver that runs in user mode on most
UNIX/Linux systems.  It also supports the 9p.2000L protocol.

For more information, consult the [project wiki](https://github.com/nfs-ganesha/nfs-ganesha/wiki).

Examples
--------
The examples show usage of TC APIs, and usually perform FS operations with much
less RPC than a standard POSIX NFS client.

- Open, read, and close a file in one RPC:
[tc_client/MainNFSD/tc_test_read.c](tc_client/MainNFSD/tc_test_read.c)

- Creating a deep directory and all its ancestor directories with only two
RPCs: [tc_client/MainNFSD/tc_test_mkdir.c](tc_client/MainNFSD/tc_test_mkdir.c)

- Creating multiple directories with only one RPC:
[tc_client/MainNFSD/tc_test_mkdirs.c](tc_client/MainNFSD/tc_test_mkdirs.c)

- Listing contents of multiple directories with one RPC:
[tc_client/MainNFSD/tc_test_listdirs.c](tc_client/MainNFSD/tc_test_listdirs.c)

LICENSE
=======
Most code in this repo has [LGPL license](tc_client/LICENSE.txt).  However, a
small number utility files has BSD license, for example,
[tc_client/util/slice.h](tc_client/util/slice.h).

Contribution
============
The project is in a very early stage; any help is greatly appreciated.
Looking forward to your git push notification :-)
