/*
*
* This is offered under a BSD-style license. This means you can use the code for whatever you
* desire in any way you may want but you MUST NOT forget to give me appropriate credits when
* spreading your work which is based on mine. Something like "original implementation by Radek
* Podgorny" should be fine.
*
* License: BSD-style license
* Copyright: Radek Podgorny <radek@podgorny.cz>,
*            Bernd Schubert <bernd-schubert@gmx.de>
*/

#if defined __linux__
	// For pread()/pwrite()/utimensat()
	#define _XOPEN_SOURCE 700

	// For chroot
	#define _BSD_SOURCE // this is deprecated since glibc 2.20 but let's keep it for a while
	#define _DEFAULT_SOURCE 1
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>
#include <pthread.h>

#ifdef linux
	#include <sys/vfs.h>
#else
	#include <sys/statvfs.h>
#endif

#ifdef HAVE_XATTR
	#include <sys/xattr.h>
#endif

#include "unionfs.h"
#include "opts.h"
#include "debug.h"
#include "findbranch.h"
#include "general.h"

#include "unlink.h"
#include "rmdir.h"
#include "readdir.h"
#include "cow.h"
#include "string.h"
#include "usyslog.h"
#include "conf.h"
#include "uioctl.h"

static int unionfs_chmod(const char *path, mode_t mode) {
	DBG("%s\n", path);

	int i = find_rw_branch_cow(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	int res = chmod(p, mode);
	if (res == -1) RETURN(-errno);

	RETURN(0);
}

static int unionfs_chown(const char *path, uid_t uid, gid_t gid) {
	DBG("%s\n", path);

	int i = find_rw_branch_cow(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	int res = lchown(p, uid, gid);
	if (res == -1) RETURN(-errno);

	RETURN(0);
}

/**
 * unionfs implementation of the create call
 * libfuse will call this to create regular files
 */
static int unionfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	DBG("%s\n", path);

	int i = find_rw_branch_cutlast(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	// NOTE: We should do:
	//       Create the file with mode=0 first, otherwise we might create
	//       a file as root + x-bit + suid bit set, which might be used for
	//       security racing!
	int res = open(p, fi->flags, 0);
	if (res == -1) RETURN(-errno);

	set_owner(p); // no error check, since creating the file succeeded

	// NOW, that the file has the proper owner we may set the requested mode
	fchmod(res, mode);

	fi->fh = res;
	remove_hidden(path, i);

	DBG("fd = %" PRIx64 "\n", fi->fh);
	RETURN(0);
}


/**
 * flush may be called multiple times for an open file, this must not really
 * close the file. This is important if used on a network filesystem like NFS
 * which flush the data/metadata on close()
 */
static int unionfs_flush(const char *path, struct fuse_file_info *fi) {
	DBG("fd = %"PRIx64"\n", fi->fh);

	int fd = dup(fi->fh);

	if (fd == -1) {
		// What to do now?
		if (fsync(fi->fh) == -1) RETURN(-EIO);

		RETURN(-errno);
	}

	int res = close(fd);
	if (res == -1) RETURN(-errno);

	RETURN(0);
}

/**
 * Just a stub. This method is optional and can safely be left unimplemented
 */
static int unionfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
	DBG("fd = %"PRIx64"\n", fi->fh);

	int res;
	if (isdatasync) {
#if _POSIX_SYNCHRONIZED_IO + 0 > 0
		res = fdatasync(fi->fh);
#else
		res = fsync(fi->fh);
#endif
	} else {
		res = fsync(fi->fh);
	}

	if (res == -1) RETURN(-errno);

	RETURN(0);
}

static int unionfs_getattr(const char *upath, struct stat *stbuf) {
	DBG("%s\n", upath);
	
	const char *path = upath;
	
	char faked_path[PATHLEN_MAX];
	if (uopt.fake_devices) {
		/* we need to replace "/proc/self" with "/proc/<pid>"
		 * to make such accesses work - the FUSE user process
		 * would otherwise always access its own pid... not good.
		 */
		if (0 == strncmp(path, "/proc/self", sizeof("/proc/self")-1)) {
			struct fuse_context *ctx = fuse_get_context();
			
			snprintf(faked_path, PATHLEN_MAX, "/proc/%d%s", ctx->pid,
			         upath+sizeof("/proc/self")-1);
			path = faked_path;
			DBG("substituted user supplied path '%s' with fake path '%s'\n", upath, path);
		}
	}

	int i = find_rorw_branch(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	int res = lstat(p, stbuf);
	if (res == -1) RETURN(-errno);

	/* This is a workaround for broken gnu find implementations. Actually,
	 * n_links is not defined at all for directories by posix. However, it
	 * seems to be common for filesystems to set it to one if the actual value
	 * is unknown. Since nlink_t is unsigned and since these broken implementations
	 * always substract 2 (for . and ..) this will cause an underflow, setting
	 * it to max(nlink_t).
	 */
	if (S_ISDIR(stbuf->st_mode)) stbuf->st_nlink = 1;

	/* check whether the user wants to report and handle device files
	 *  as if they were regular files
	 */
	if (   uopt.fake_devices 
	    && (S_ISCHR(stbuf->st_mode) || S_ISBLK(stbuf->st_mode))
		) {
		stbuf->st_rdev = 0;
		stbuf->st_mode = (stbuf->st_mode & (~S_IFMT)) | S_IFREG;
	}
	
	RETURN(0);
}

static int unionfs_access(const char *path, int mask) {
	struct stat s;

	if (unionfs_getattr(path, &s) != 0)
		RETURN(-ENOENT);

	if ((mask & X_OK) && (s.st_mode & S_IXUSR) == 0)
		RETURN(-EACCES);

	if ((mask & W_OK) && (s.st_mode & S_IWUSR) == 0)
		RETURN(-EACCES);

	if ((mask & R_OK) && (s.st_mode & S_IRUSR) == 0)
		RETURN(-EACCES);

	RETURN(0);
}

/**
 * init method
 * called before first access to the filesystem
 */
static void * unionfs_init(struct fuse_conn_info *conn) {
	// just to prevent the compiler complaining about unused variables
	(void) conn->max_readahead;

	// we only now (from unionfs_init) may go into the chroot, since otherwise
	// fuse_main() will fail to open /dev/fuse and to call mount
	if (uopt.chroot) {
		int res = chroot(uopt.chroot);
		if (res) {
			USYSLOG(LOG_WARNING, "Chdir to %s failed: %s ! Aborting!\n",
				 uopt.chroot, strerror(errno));
			exit(1);
		}
	}

#ifdef FUSE_CAP_IOCTL_DIR
	if (conn->capable & FUSE_CAP_IOCTL_DIR)
		conn->want |= FUSE_CAP_IOCTL_DIR;
#endif

	return NULL;
}

static int unionfs_link(const char *from, const char *to) {
	DBG("from %s to %s\n", from, to);

	// hardlinks do not work across different filesystems so we need a copy of from first
	int i = find_rw_branch_cow(from);
	if (i == -1) RETURN(-errno);

	int j = __find_rw_branch_cutlast(to, i);
	if (j == -1) RETURN(-errno);

	DBG("from branch: %d to branch: %d\n", i, j);

	char f[PATHLEN_MAX], t[PATHLEN_MAX];
	if (BUILD_PATH(f, uopt.branches[i].path, from)) RETURN(-ENAMETOOLONG);
	if (BUILD_PATH(t, uopt.branches[j].path, to)) RETURN(-ENAMETOOLONG);

	int res = link(f, t);
	if (res == -1) RETURN(-errno);

	// no need for set_owner(), since owner and permissions are copied over by link()

	remove_hidden(to, i); // remove hide file (if any)
	RETURN(0);
}

static const char * ioctl_direction_names[4] = {
	"none",
	"write",
	"read",
	"read/write"
};


#if FUSE_VERSION >= 28

/* includes required for ioctl parameter knowledge: */
#include <sys/ioctl.h>

static int unionfs_ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, void *data) {
	(void) path;
	(void) arg; // avoid compiler warning
	(void) fi;  // avoid compiler warning

	DBG("got ioctl: path=%s cmd=%d (direction=%s, type=%d, nr=%d, size=%d) arg=%p, flags=%d, data=%p \n",
	    path, cmd, ioctl_direction_names[_IOC_DIR(cmd)], _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd), arg, flags, data);
	
	
#ifdef FUSE_IOCTL_COMPAT // 32bit-mode within 64-bit
	if (flags & FUSE_IOCTL_COMPAT)
		return -ENOSYS;
#endif
	
	
	if (uopt.fake_devices) {
		/* we can process ioctl's from the accessing process only
		 * if we can read its memory (via /proc/<pid>/mem)
		 */
		
		struct fuse_context *ctx = fuse_get_context();
		
		char proc_pid_mem_name[PATHLEN_MAX];
		snprintf(proc_pid_mem_name, PATHLEN_MAX, "/proc/%d/mem", ctx->pid);
		
		int proc_pid_mem_fd = open(proc_pid_mem_name, O_RDWR);
		if (proc_pid_mem_fd == -1) {
			DBG("cannot open %s to process ioctl %d\n", proc_pid_mem_name, cmd);
			return -EFAULT;
		}
		
		int res = -ENOSYS;
		
		switch (cmd) {
		
		case TCGETS: {
			off_t  addr_par_1 = (off_t)arg;
			const size_t size_par_1 = 36; /* == real sizeof(struct termios) - not 44 bytes!  */
			char ioctl_par_1[size_par_1] __attribute__ ((aligned (64)));
			
			res = ioctl(fi->fh, cmd, &ioctl_par_1);
			
			if (size_par_1 != pwrite(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				DBG("cannot pwrite %zd bytes to %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				res = -EFAULT;
				break;
			}
			
			break;
		}
		
		case TCSETS: {
			off_t  addr_par_1 = (off_t)arg;
			const size_t size_par_1 = 36; /* == real sizeof(struct termios) - not 44 bytes!  */
			char ioctl_par_1[size_par_1] __attribute__ ((aligned (64)));
			
			if (size_par_1 != pread(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				res = -EFAULT;
				DBG("cannot pread %zd bytes from %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				break;
			}
			
			res = ioctl(fi->fh, cmd, &ioctl_par_1);
			break;
		}

		case TIOCGSERIAL: {
			off_t  addr_par_1 = (off_t)arg;
			const size_t size_par_1 = 72; /* == sizeof(struct serial_struct)  */
			char ioctl_par_1[size_par_1] __attribute__ ((aligned (64)));
			
			res = ioctl(fi->fh, cmd, &ioctl_par_1);
			
			if (size_par_1 != pwrite(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				DBG("cannot pwrite %zd bytes to %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				res = -EFAULT;
				break;
			}
			
			break;
		}
		
		case TIOCSSERIAL: {
			off_t  addr_par_1 = (off_t)arg;
			const size_t size_par_1 = 72; /* == sizeof(struct serial_struct)  */
			char ioctl_par_1[size_par_1] __attribute__ ((aligned (64)));
			
			if (size_par_1 != pread(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				res = -EFAULT;
				DBG("cannot pread %zd bytes from %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				break;
			}
			
			res = ioctl(fi->fh, cmd, &ioctl_par_1);
			break;
		}

		case SIOCGIFHWADDR: {
			off_t  addr_par_1 = (off_t)arg;
			const size_t size_par_1 = 40;  /* sizeof(struct ifreq) */
			char ioctl_par_1[size_par_1] __attribute__ ((aligned (64)));
			
			if (size_par_1 != pread(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				res = -EFAULT;
				DBG("cannot pread %zd bytes from %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				break;
			}
			
			res = ioctl(fi->fh, cmd, &ioctl_par_1);
			
			if (size_par_1 != pwrite(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				DBG("cannot pwrite %zd bytes to %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				res = -EFAULT;
				break;
			}
			
			break;
		}
		
		case TIOCOUTQ:
		case TIOCMGET:
		/* case TIOCINQ: - same as FIONREAD */
		case FIONREAD: {
			off_t  addr_par_1 = (off_t)arg;
			const size_t size_par_1 = sizeof(int);
			char ioctl_par_1[size_par_1] __attribute__ ((aligned (64)));
			
			res = ioctl(fi->fh, cmd, &ioctl_par_1);
			
			if (size_par_1 != pwrite(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				DBG("cannot pwrite %zd bytes to %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				res = -EFAULT;
				break;
			}
			
			break;
		}

		case TIOCMBIS:
		case TIOCMBIC: {
			off_t  addr_par_1 = (off_t)arg;
			const size_t size_par_1 = sizeof(int);
			char ioctl_par_1[size_par_1] __attribute__ ((aligned (64)));
			
			if (size_par_1 != pread(proc_pid_mem_fd, &ioctl_par_1, size_par_1, addr_par_1)) {
				res = -EFAULT;
				DBG("cannot pread %zd bytes from %p in %s for ioctl %d, reason: %s\n",
				    size_par_1, arg, proc_pid_mem_name, cmd, strerror(errno));
				break;
			}
			
			res = ioctl(fi->fh, cmd, &ioctl_par_1);
			break;
		}

		case TCFLSH:
		case TCSBRK: {
			const int i = (int)((long long)arg);			
			res = ioctl(fi->fh, cmd, i);
			break;
		}
		
		case TIOCEXCL:
		case TIOCNXCL: {
			res = ioctl(fi->fh, cmd);
			break;
		}
		
		default:
			/* IOCTL "cmd" is not yet supported here */
			DBG("ioctl %d is not yet supported - feel free to enhance unionfs-fuse/src/fuse_ops.c\n", cmd); 
		}
		
		close(proc_pid_mem_fd);
		
		return res;	
	}
	
	
	switch (cmd) {
	case UNIONFS_ONOFF_DEBUG: {
		int on_off = *((int *) data);
		// unionfs-ctl gives the opposite value, so !!
		bool setRes = set_debug_onoff(!!on_off);
		if (!setRes)
			return -EINVAL;
		return 0;
	}
	case UNIONFS_SET_DEBUG_FILE: {
		char *debug_path = (char *) data;

		set_debug_path(debug_path, _IOC_SIZE(cmd));

		debug_init();
		return 0;
	}
	default:
		USYSLOG(LOG_ERR, "Unknown ioctl: %d", cmd);
		return -EINVAL;
		break;
	}

	return 0;
}
#endif

/**
 * unionfs mkdir() implementation
 *
 * NOTE: Never delete whiteouts directories here, since this will just
 *       make already hidden sub-branches visible again.
 */
static int unionfs_mkdir(const char *path, mode_t mode) {
	DBG("%s\n", path);

	int i = find_rw_branch_cutlast(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	int res = mkdir(p, 0);
	if (res == -1) RETURN(-errno);

	set_owner(p); // no error check, since creating the file succeeded
	// NOW, that the file has the proper owner we may set the requested mode
	chmod(p, mode);

	RETURN(0);
}

static int unionfs_mknod(const char *path, mode_t mode, dev_t rdev) {
	DBG("%s\n", path);

	int i = find_rw_branch_cutlast(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	int file_type = mode & S_IFMT;
	int file_perm = mode & (S_PROT_MASK);

	int res = -1;
	if ((file_type) == S_IFREG) {
		// under FreeBSD, only the super-user can create ordinary files using mknod
		// Actually this workaround should not be required any more
		// since we now have the unionfs_create() method
		// So can we remove it?

		USYSLOG (LOG_INFO, "deprecated mknod workaround, tell the unionfs-fuse authors if you see this!\n");

		res = creat(p, 0);
		if (res > 0 && close(res) == -1) USYSLOG(LOG_WARNING, "Warning, cannot close file\n");
	} else {
		res = mknod(p, file_type, rdev);
	}

	if (res == -1) RETURN(-errno);

	set_owner(p); // no error check, since creating the file succeeded
	// NOW, that the file has the proper owner we may set the requested mode
	chmod(p, file_perm);

	remove_hidden(path, i);

	RETURN(0);
}

static int unionfs_open(const char *upath, struct fuse_file_info *fi) {
	DBG("%s\n", upath);
	
	const char * path = upath;
	
	char faked_path[PATHLEN_MAX];
	if (uopt.fake_devices) {
		/* we need to replace "/proc/self" with "/proc/<pid>"
		 * to make such accesses work - the FUSE user process
		 * would otherwise always access its own pid... not good.
		 */
		if (0 == strncmp(path, "/proc/self", sizeof("/proc/self")-1)) {
			struct fuse_context *ctx = fuse_get_context();
			
			snprintf(faked_path, PATHLEN_MAX, "/proc/%d%s", ctx->pid,
			         upath+sizeof("/proc/self")-1);
			path = faked_path;
			DBG("substituted user supplied path '%s' with fake path '%s'\n", upath, path);
		}
	}
	

	int i;
	if (fi->flags & (O_WRONLY | O_RDWR)) {
		i = find_rw_branch_cutlast(path);
	} else {
		i = find_rorw_branch(path);
	}

	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	/* if the user wants us to open a device file
	 * as if it was a regular file, we need to take
	 * care that data is directly read/written and 
	 * that no attempts on caching/seeking are made 
	 */
	if (uopt.fake_devices) {
		
		struct stat statbuf;
		
		int res = lstat(p, &statbuf);
		if (res == -1) RETURN(-errno);
		
		if (statbuf.st_size == 0 || S_ISCHR(statbuf.st_mode) || S_ISBLK(statbuf.st_mode)) {
			/* we do not care here that exec() is reported not to
			 * work with fi->direct_io = 1, as exec() of a device
			 * file or a zero-sized file sounds implausible, anyway
			 */
			fi->direct_io = 1;
			fi->nonseekable = 1;
		}
	}

	int fd = open(p, fi->flags);
	if (fd == -1) RETURN(-errno);

	if (fi->flags & (O_WRONLY | O_RDWR)) {
		// There might have been a hide file, but since we successfully
		// wrote to the real file, a hide file must not exist anymore
		remove_hidden(path, i);
	}

	// This makes exec() fail
	//fi->direct_io = 1;
	fi->fh = (unsigned long)fd;

	DBG("fd = %"PRIx64"\n", fi->fh);
	RETURN(0);
}


// mutex to protectect the observer-related data structures below
pthread_mutex_t poll_observer_mutex; 

// file descriptors of a pipe the poll_observer thread (also) waits for,
// and the unionfs main thread writes to wake up the poll_observer when
// another call to unionfs_poll indicates more/changed work to do
int poll_observer_pipe[2]; 

// if file descriptor X is to be observed for poll() notifications,
//  poll_handle[X] will contain a fuse_pollhandle * for this - or a zero-pointer if not.
struct fuse_pollhandle ** poll_handles;
short * poll_revents; // what to poll() for, also used to convey result, same size as poll_handles
unsigned int poll_handles_size; // poll_handles is dynamically enlarged if required for a higher fd

static int observer_lock(void) {
	int error_number = 0;
	char error_msg_buf[4096];
	
	error_number = pthread_mutex_lock(&poll_observer_mutex);
	if (error_number) {
		if (0 == strerror_r(error_number, error_msg_buf, sizeof(error_msg_buf))) {
			fprintf(stderr, "observer_lock: pthread_mutex_lock failed: %s\n", error_msg_buf);
		}
		return -1;
	}
	return 0;
}

static int observer_unlock(void) {
	int error_number = 0;
	char error_msg_buf[4096];
	
	error_number = pthread_mutex_unlock(&poll_observer_mutex);
	if (error_number) {
		if (0 == strerror_r(error_number, error_msg_buf, sizeof(error_msg_buf))) {
			fprintf(stderr, "observer_lock: pthread_mutex_lock failed: %s\n", error_msg_buf);
		}
		return -1;
	}
	return 0;
}

#include <poll.h>

static int unionfs_poll(const char *path, struct fuse_file_info *fi,
                     struct fuse_pollhandle *ph, unsigned *reventsp)
{
	if (observer_lock()) {
		RETURN(-ENOSYS);
	}
	
	// we need to make sure that our data structures are big enough to 
	// contain the file descriptor fi->fh
	if (fi->fh >= poll_handles_size) {
		// nope, need to enlarge the structures
		
		size_t new_size = fi->fh + 8; // the "+8" is just meant to reduce the number of re-allocations / copies
		
		DBG("resizing poll_handles from %u to %zd\n", poll_handles_size, new_size);
		
		struct fuse_pollhandle ** new_poll_handles = malloc(new_size * sizeof(struct fuse_pollhandle *));
		if (new_poll_handles == 0) {
			fprintf(stderr, "unionfs_poll: malloc(%zd) failed\n", new_size * sizeof(struct fuse_pollhandle *));
			observer_unlock();			
			RETURN(-ENOSYS);
		}
		if (poll_handles != 0) {
			memcpy(new_poll_handles, poll_handles, poll_handles_size * sizeof(struct fuse_pollhandle *));
			free(poll_handles);
		}
		memset(((char *)new_poll_handles) + poll_handles_size * sizeof(struct fuse_pollhandle *),
		       0, (new_size - poll_handles_size) * sizeof(struct fuse_pollhandle *));
		poll_handles = new_poll_handles;
		
		short * new_poll_revents = malloc(new_size * sizeof(short));
		if (new_poll_revents == 0) {
			fprintf(stderr, "unionfs_poll: malloc(%zd) failed\n", new_size * sizeof(short));
			observer_unlock();			
			RETURN(-ENOSYS);
		}
		if (poll_revents != 0) {
			memcpy(new_poll_revents, poll_revents, poll_handles_size * sizeof(short));
			free(poll_revents);
		}
		memset(((char *)new_poll_revents) + poll_handles_size * sizeof(short),
		       0, (new_size - poll_handles_size) * sizeof(short));
		poll_revents = new_poll_revents;
		
		poll_handles_size = new_size;
	}
	
	if (ph != NULL) {
		// before storing the fuse_pollhandle for later notification use
		// by the poll_observer_function, we need to take care that any
		// pre-existing fuse_pollhandle for the same file descriptor
		// is properly destroyed
		if (poll_handles[fi->fh] != 0) {
			fuse_pollhandle_destroy(poll_handles[fi->fh]);
		}
	}
	poll_handles[fi->fh] = ph;		
	
	unsigned int events_last_returned = poll_revents[fi->fh];
	unsigned int events_last_asked = *reventsp;
	
	poll_revents[fi->fh] = events_last_asked; // in case that reventsp is an input parameter
	*reventsp = events_last_returned;         // in case that reventsp is an output parameter
	
	DBG("fd = %"PRIx64" path=%s ph=%p events_last_asked=%ud events_last_returned=%ud\n",
	    fi->fh, path, ph, events_last_asked, events_last_returned);
	
	// make the poll_observer thread wake up from its own poll() call,
	// to consider any changes we did to poll_handles and poll_revents
	char dummybyte = 0x55;
	write(poll_observer_pipe[1], &dummybyte, 1);
	
	if (observer_unlock()) {
		RETURN(-ENOSYS);
	}
	
	return 0;
}

void *poll_observer_function(void *data)
{
	nfds_t pfds_array_size = 0;
	struct pollfd * pfds = 0;
	
	for (;;) {
		
		// obtain the mutex for the observer related data structures
		// to avoid races with unionfs_poll() activity 
		if (observer_lock()) {
			return ((void *)1);
		}
		
		// compute the number of pollfd structures we will need
		// for our next call to poll()
		nfds_t new_pfds_size = 1 + poll_handles_size;
		
		if (new_pfds_size != pfds_array_size) {
			
			DBG("changing pfds_array_size from %lu to %lu\n", pfds_array_size, new_pfds_size);
			
			// we need a differently sized pollfd array than before
			if (pfds != 0) {
				// get rid of now obsolete pollfd array
				free(pfds);
				pfds = 0;
			}
			pfds = malloc(new_pfds_size * sizeof(struct pollfd));
			if (pfds == 0) {
				fprintf(stderr, "poll_observer_function: malloc(%zd) failed\n", new_pfds_size * sizeof(struct pollfd));
				return ((void *)1);
			}
			
			// the first pollfd structure is used to wait for read()ability of
			// the pipe to us
			pfds[0].fd = poll_observer_pipe[0];
			pfds[0].events = POLLIN;
			pfds[0].revents = 0;
			
			pfds_array_size = new_pfds_size;
		}
		
		// set or update pfds[1 .. new_pfds_size-1]
		
		// pfds[1 .. new_pfds_size-1] are used to (potentially) poll for any
		// file descriptor the unionfs clients want to poll() for -
		// notice the index into poll_handles[] is directly the file descriptor value
		nfds_t i;
		for (i = 1; i < new_pfds_size; i++) {
			if (poll_handles[i-1] == 0) {
				// ok, so no polling for file descriptor (i-1)
				pfds[i].fd = -1; // according to the poll() man-page, this tells poll() to ignore this pollfd
			} else {
				pfds[i].fd = i-1;
			}
			pfds[i].events = poll_revents[i-1];
			pfds[i].revents = 0;
		}
		
		// at this point, we have a properly sized and initialized "pfds" array
		
		// release the mutex for the observer related data structures
		if (observer_unlock()) {
			return ((void *)1);
		}
		
		int res = poll(pfds, pfds_array_size, 100000);
		DBG("observer: poll returned, res=%d, pfds[0].revents=%ud\n", res, pfds[0].revents);
		if (res < 0) {
			fprintf(stderr, "poll_observer_function: poll() failed: %s\n", strerror(errno));
			return ((void *)1);
		}
		
		if (pfds[0].events | POLLIN) {
			// observer thread was sent some dummy data to wake it up,
			// just read stuff (non-blocking) from the pipe to empty it
			char dummy_bytes[16];
			read(poll_observer_pipe[0], dummy_bytes, 16);
		}
		
		if (observer_lock()) {
			return ((void *)1);
		}
				
		// iterate over all pollfd structures to see if action is to be taken
		for (i = 1; i < pfds_array_size; i++) {
			if (poll_handles[i-1] == 0) {
				// their either was or is no interest in polling fd = i-1 now
				pfds[i].fd = -1;
			
			} else {
				// is an event signaled for the stake holder?	
				if (pfds[i].revents != 0) {
					poll_revents[i-1] = pfds[i].revents;
					
					DBG("observer: notifying revents=%d for fd=%lu\n", poll_revents[i-1], i-1);
					fuse_notify_poll(poll_handles[i-1]);
					fuse_pollhandle_destroy(poll_handles[i-1]);
					
					poll_handles[i-1] = 0;
					
					// after notification, we don't need to keep polling for the same event
					pfds[i].fd = -1;
				}
			}
		}
		
		if (observer_unlock()) {
			return ((void *)1);
		}
	}
	
	// will never reach this:
	return NULL;
}

static int unionfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	DBG("fd = %"PRIx64" path=%s size=%zd offset=%zd fi->nonseekable=%d \n", fi->fh, path, size, offset, fi->nonseekable);
	
	int res;
	
	if (uopt.fake_devices) {
		if (lseek(fi->fh, offset, SEEK_SET) < 0) {
			/* for -o fake_devices, we are ok that some files are just not seekable */
			if (errno != ESPIPE) {
				RETURN(-errno);
			}
		}
		
		res = read(fi->fh, buf, size);	
	} else {
		/* without -o fake_devices, seekability is mandatory */
		res = pread(fi->fh, buf, size, offset);
	}
	
	if (res == -1) RETURN(-errno);

	RETURN(res);
}

static int unionfs_readlink(const char *path, char *buf, size_t size) {
	DBG("%s\n", path);

	int i = find_rorw_branch(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	int res = readlink(p, buf, size - 1);

	if (res == -1) RETURN(-errno);

	buf[res] = '\0';

	RETURN(0);
}

static int unionfs_release(const char *path, struct fuse_file_info *fi) {
	DBG("fd = %"PRIx64"\n", fi->fh);
	
	// we need to remove a possible registered stake in poll() events
	if (observer_lock()) {
		return -ENOSYS;
	}
	if (fi->fh < poll_handles_size) {
		if (poll_handles[fi->fh] != 0) {
			fuse_pollhandle_destroy(poll_handles[fi->fh]);
			poll_handles[fi->fh] = 0;
			
			// make the poll_observer thread wake up from its own poll() call
			char dummybyte = 0x55;
			write(poll_observer_pipe[1], &dummybyte, 1);
		}
	}
	
	if (observer_unlock()) {
		return -ENOSYS;
	}
	
	int res = close(fi->fh);
	if (res == -1) RETURN(-errno);

	RETURN(0);
}

/**
 * unionfs rename function
 * TODO: If we rename a directory on a read-only branch, we need to copy over
 *       all files to the renamed directory on the read-write branch.
 */
static int unionfs_rename(const char *from, const char *to) {
	DBG("from %s to %s\n", from, to);

	bool is_dir = false; // is 'from' a file or directory

	int j = find_rw_branch_cutlast(to);
	if (j == -1) RETURN(-errno);

	int i = find_rorw_branch(from);
	if (i == -1) RETURN(-errno);

	if (!uopt.branches[i].rw) {
		i = find_rw_branch_cow_common(from, true);
		if (i == -1) RETURN(-errno);
	}

	if (i != j) {
		USYSLOG(LOG_ERR, "%s: from and to are on different writable branches %d vs %d, which"
		       "is not supported yet.\n", __func__, i, j);
		RETURN(-EXDEV);
	}

	char f[PATHLEN_MAX], t[PATHLEN_MAX];
	if (BUILD_PATH(f, uopt.branches[i].path, from)) RETURN(-ENAMETOOLONG);
	if (BUILD_PATH(t, uopt.branches[i].path, to)) RETURN(-ENAMETOOLONG);

	filetype_t ftype = path_is_dir(f);
	if (ftype == NOT_EXISTING)
		RETURN(-ENOENT);
	else if (ftype == IS_DIR)
		is_dir = true;

	int res;
	if (!uopt.branches[i].rw) {
		// since original file is on a read-only branch, we copied the from file to a writable branch,
		// but since we will rename from, we also need to hide the from file on the read-only branch
		if (is_dir)
			res = hide_dir(from, i);
		else
			res = hide_file(from, i);
		if (res) RETURN(-errno);
	}

	res = rename(f, t);

	if (res == -1) {
		int err = errno; // unlink() might overwrite errno
		// if from was on a read-only branch we copied it, but now rename failed so we need to delete it
		if (!uopt.branches[i].rw) {
			if (unlink(f))
				USYSLOG(LOG_ERR, "%s: cow of %s succeeded, but rename() failed and now "
				       "also unlink()  failed\n", __func__, from);

			if (remove_hidden(from, i))
				USYSLOG(LOG_ERR, "%s: cow of %s succeeded, but rename() failed and now "
				       "also removing the whiteout  failed\n", __func__, from);
		}
		RETURN(-err);
	}

	if (uopt.branches[i].rw) {
		// A lower branch still *might* have a file called 'from', we need to delete this.
		// We only need to do this if we have been on a rw-branch, since we created
		// a whiteout for read-only branches anyway.
		if (is_dir)
			maybe_whiteout(from, i, WHITEOUT_DIR);
		else
			maybe_whiteout(from, i, WHITEOUT_FILE);
	}

	remove_hidden(to, i); // remove hide file (if any)
	RETURN(0);
}

/**
 * Wrapper function to convert the result of statfs() to statvfs()
 * libfuse uses statvfs, since it conforms to POSIX. Unfortunately,
 * glibc's statvfs parses /proc/mounts, which then results in reading
 * the filesystem itself again - which would result in a deadlock.
 * TODO: BSD/MacOSX
 */
static int statvfs_local(const char *path, struct statvfs *stbuf) {
#ifdef linux
	/* glibc's statvfs walks /proc/mounts and stats entries found there
	 * in order to extract their mount flags, which may deadlock if they
	 * are mounted under the unionfs. As a result, we have to do this
	 * ourselves.
	 */
	struct statfs stfs;
	int res = statfs(path, &stfs);
	if (res == -1) RETURN(res);

	memset(stbuf, 0, sizeof(*stbuf));
	stbuf->f_bsize = stfs.f_bsize;
	if (stfs.f_frsize) {
		stbuf->f_frsize = stfs.f_frsize;
	} else {
		stbuf->f_frsize = stfs.f_bsize;
	}
	stbuf->f_blocks = stfs.f_blocks;
	stbuf->f_bfree = stfs.f_bfree;
	stbuf->f_bavail = stfs.f_bavail;
	stbuf->f_files = stfs.f_files;
	stbuf->f_ffree = stfs.f_ffree;
	stbuf->f_favail = stfs.f_ffree; /* nobody knows */

	/* We don't worry about flags, exactly because this would
	 * require reading /proc/mounts, and avoiding that and the
	 * resulting deadlocks is exactly what we're trying to avoid
	 * by doing this rather than using statvfs.
	 */
	stbuf->f_flag = 0;
	stbuf->f_namemax = stfs.f_namelen;

	RETURN(0);
#else
	RETURN(statvfs(path, stbuf));
#endif
}

/**
 * statvs implementation
 *
 * Note: We do not set the fsid, as fuse ignores it anyway.
 */
static int unionfs_statfs(const char *path, struct statvfs *stbuf) {
	(void)path;

	DBG("%s\n", path);

	int first = 1;

	dev_t devno[uopt.nbranches];

	int retVal = 0;

	int i = 0;
	for (i = 0; i < uopt.nbranches; i++) {
		struct statvfs stb;
		int res = statvfs_local(uopt.branches[i].path, &stb);
		if (res == -1) {
			retVal = -errno;
			break;
		}

		struct stat st;
		res = stat(uopt.branches[i].path, &st);
		if (res == -1) {
			retVal = -errno;
			break;
		}
		devno[i] = st.st_dev;

		if (first) {
			memcpy(stbuf, &stb, sizeof(*stbuf));
			first = 0;
			stbuf->f_fsid = stb.f_fsid << 8;
			continue;
		}

		// Eliminate same devices
		int j = 0;
		for (j = 0; j < i; j ++) {
			if (st.st_dev == devno[j]) break;
		}

		if (j == i) {
			// Filesystem can have different block sizes -> normalize to first's block size
			double ratio = (double)stb.f_bsize / (double)stbuf->f_bsize;

			if (uopt.branches[i].rw) {
				stbuf->f_blocks += stb.f_blocks * ratio;
				stbuf->f_bfree += stb.f_bfree * ratio;
				stbuf->f_bavail += stb.f_bavail * ratio;

				stbuf->f_files += stb.f_files;
				stbuf->f_ffree += stb.f_ffree;
				stbuf->f_favail += stb.f_favail;
			} else if (!uopt.statfs_omit_ro) {
				// omitting the RO branches is not correct regarding
				// the block counts but it actually fixes the
				// percentage of free space. so, let the user decide.
				stbuf->f_blocks += stb.f_blocks * ratio;
				stbuf->f_files  += stb.f_files;
			}

			if (!(stb.f_flag & ST_RDONLY)) stbuf->f_flag &= ~ST_RDONLY;
			if (!(stb.f_flag & ST_NOSUID)) stbuf->f_flag &= ~ST_NOSUID;

			if (stb.f_namemax < stbuf->f_namemax) stbuf->f_namemax = stb.f_namemax;
		}
	}

	RETURN(retVal);
}

static int unionfs_symlink(const char *from, const char *to) {
	DBG("from %s to %s\n", from, to);

	int i = find_rw_branch_cutlast(to);
	if (i == -1) RETURN(-errno);

	char t[PATHLEN_MAX];
	if (BUILD_PATH(t, uopt.branches[i].path, to)) RETURN(-ENAMETOOLONG);

	int res = symlink(from, t);
	if (res == -1) RETURN(-errno);

	set_owner(t); // no error check, since creating the file succeeded

	remove_hidden(to, i); // remove hide file (if any)
	RETURN(0);
}

static int unionfs_truncate(const char *path, off_t size) {
	DBG("%s\n", path);

	int i = find_rw_branch_cow(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

	if (uopt.fake_devices) {
		
		struct stat statbuf;
		
		int res = lstat(p, &statbuf);
		if (res == -1) RETURN(-errno);
		
		if (S_ISCHR(statbuf.st_mode) || S_ISBLK(statbuf.st_mode)) {
			/* device files cannot be truncated - so if this
			 * is about a faked device file, we just pretend
			 * the truncate "worked"
			 */
			RETURN(0);
		}
	}

	int res = truncate(p, size);

	if (res == -1) RETURN(-errno);

	RETURN(0);
}

static int unionfs_utimens(const char *path, const struct timespec ts[2]) {
	DBG("%s\n", path);

	int i = find_rw_branch_cow(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

#ifdef UNIONFS_HAVE_AT
	int res = utimensat(0, p, ts, AT_SYMLINK_NOFOLLOW);
#else
	struct timeval tv[2];
	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;
	int res = utimes(p, tv);
#endif

	if (res == -1) RETURN(-errno);

	RETURN(0);
}

static int unionfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	(void)path;
	
	DBG("fd = %"PRIx64" path=%s size=%zd offset=%zd \n", fi->fh, path, size, offset);
	
	int res;
	
	if (uopt.fake_devices) {
		if (lseek(fi->fh, offset, SEEK_SET) < 0) {
			/* for -o fake_devices, we are ok that some files are just not seekable */
			if (errno != ESPIPE) {
				RETURN(-errno);
			}
		}
		
		res = write(fi->fh, buf, size);	
	} else {
		res = pwrite(fi->fh, buf, size, offset);
	}
	
	if (res == -1) RETURN(-errno);
	
	RETURN(res);
}

#ifdef HAVE_XATTR

#if __APPLE__
static int unionfs_getxattr(const char *path, const char *name, char *value, size_t size, uint32_t position) {
#else
static int unionfs_getxattr(const char *path, const char *name, char *value, size_t size) {
#endif
	DBG("%s\n", path);

	int i = find_rorw_branch(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

#if __APPLE__
	int res = getxattr(p, name, value, size, position, XATTR_NOFOLLOW);
#else
	int res = lgetxattr(p, name, value, size);
#endif

	if (res == -1) RETURN(-errno);

	RETURN(res);
}

static int unionfs_listxattr(const char *path, char *list, size_t size) {
	DBG("%s\n", path);

	int i = find_rorw_branch(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

#if __APPLE__
	int res = listxattr(p, list, size, XATTR_NOFOLLOW);
#else
	int res = llistxattr(p, list, size);
#endif

	if (res == -1) RETURN(-errno);

	RETURN(res);
}

static int unionfs_removexattr(const char *path, const char *name) {
	DBG("%s\n", path);

	int i = find_rw_branch_cow(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

#if __APPLE__
	int res = removexattr(p, name, XATTR_NOFOLLOW);
#else
	int res = lremovexattr(p, name);
#endif

	if (res == -1) RETURN(-errno);

	RETURN(res);
}

#if __APPLE__
static int unionfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags, uint32_t position) {
#else
static int unionfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
#endif
	DBG("%s\n", path);

	int i = find_rw_branch_cow(path);
	if (i == -1) RETURN(-errno);

	char p[PATHLEN_MAX];
	if (BUILD_PATH(p, uopt.branches[i].path, path)) RETURN(-ENAMETOOLONG);

#if __APPLE__
	int res = setxattr(p, name, value, size, position, flags | XATTR_NOFOLLOW);
#else
	int res = lsetxattr(p, name, value, size, flags);
#endif

	if (res == -1) RETURN(-errno);

	RETURN(res);
}
#endif // HAVE_XATTR

struct fuse_operations unionfs_oper = {
	.chmod = unionfs_chmod,
	.chown = unionfs_chown,
	.create = unionfs_create,
	.flush = unionfs_flush,
	.fsync = unionfs_fsync,
	.getattr = unionfs_getattr,
	.access = unionfs_access,
	.init = unionfs_init,
#if FUSE_VERSION >= 28
	.ioctl = unionfs_ioctl,
#endif
	.link = unionfs_link,
	.mkdir = unionfs_mkdir,
	.mknod = unionfs_mknod,
	.open = unionfs_open,
	.poll = unionfs_poll,
	.read = unionfs_read,
	.readlink = unionfs_readlink,
	.readdir = unionfs_readdir,
	.release = unionfs_release,
	.rename = unionfs_rename,
	.rmdir = unionfs_rmdir,
	.statfs = unionfs_statfs,
	.symlink = unionfs_symlink,
	.truncate = unionfs_truncate,
	.unlink = unionfs_unlink,
	.utimens = unionfs_utimens,
	.write = unionfs_write,
#ifdef HAVE_XATTR
	.getxattr = unionfs_getxattr,
	.listxattr = unionfs_listxattr,
	.removexattr = unionfs_removexattr,
	.setxattr = unionfs_setxattr,
#endif
};
