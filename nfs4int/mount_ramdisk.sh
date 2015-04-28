#!/bin/bash

set -x
umount /vfs-ganesha/
targetcli restoreconfig pi-10GB-device-config.json clear_existing
yes | mkfs.ext4 /dev/sdb
mount -t ext4 /dev/sdb  /vfs-ganesha/
#tmux -2

