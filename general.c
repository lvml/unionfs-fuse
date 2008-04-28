/*
*  C Implementation: general
*
* Description: General functions, not directly related to file system operations
*
* original implementation by Radek Podgorny
*
* License: BSD-style license
* Copyright: Radek Podgorny <radek@podgorny.cz>,
*            Bernd Schubert <bernd-schubert@gmx.de>
*
*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>

#include "unionfs.h"
#include "opts.h"


static uid_t daemon_uid = -1; // the uid the daemon is running as
static pthread_mutex_t mutex; // the to_user() and to_root() locking mutex


/**
 * arguments: maximal string length and one or more char* string arrays
 *
 * check if the sum of the strings is larger than PATHLEN_MAX
 *
 * This function requires a NULL as last argument!
 */
bool string_too_long(int max_len, ...)
{
	va_list ap; // argument pointer
	int len = 0;
	int i = 0;

	va_start(ap, max_len);
	while (1) {
		char *str = va_arg (ap, char *);
		if (!str) break;

		i++;
		len += strlen(str);
	}

	if (len >= max_len)
		return true;

	return false;
}

/**
 * Check if the given fname suffixes the hide tag
 */
char *whiteout_tag(const char *fname) {
	char *tag = strstr(fname, HIDETAG);

	// check if fname has tag, fname is not only the tag, file name ends with the tag
	// TODO: static strlen(HIDETAG)
	if (tag && tag != fname && strlen(tag) == strlen(HIDETAG)) {
		return tag;
	}

	return NULL;
}


/**
 * Check if a file or directory with the hidden flag exists.
 */
static bool filedir_hidden(const char *path) {
	// cow mode disabled, no need for hidden files
	if (!uopt.cow_enabled) return false;
	
	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", path, HIDETAG);

	struct stat stbuf;
	int res = lstat(p, &stbuf);
	if (res == 0) return true;

	return false;
}


/**
 * check if any dir or file within path is hidden
 */
bool path_hidden(const char *path) {
	if (!uopt.cow_enabled) return false;

	char *walk = (char *)path;

	// first slashes, e.g. we have path = /dir1/dir2/, will set walk = dir1/dir2/
	while (*walk != '\0' && *walk == '/') walk++;

	bool first = true; 
	do {
		// walk over the directory name, walk will now be /dir2
		while (*walk != '\0' && *walk != '/') walk++;
	
		if (first) {
			// first dir in path is our branch, no need to check if it is hidden
			first = false;
			continue;
		}
		// +1 due to \0, which gets added automatically
		char p[PATHLEN_MAX];
		snprintf(p, (walk - path) + 1, "%s", path); // walk - path = strlen(/dir1)
		bool res = filedir_hidden(p);
		if (res) return res; // path is hidden

		// as above the do loop, walk over the next slashes, walk = dir2/
		while (*walk != '\0' && *walk == '/') walk++;
	} while (*walk != '\0');

	return 0;
}


/**
 * Remove a hide-file in all roots up to maxroot
 * If maxroot == -1, try to delete it in all roots.
 */
int remove_hidden(const char *path, int maxroot) {
	if (!uopt.cow_enabled) return 0;

	if (maxroot == -1) maxroot = uopt.nroots;

	int i;
	for (i = 0; i <= maxroot; i++) {
		char p[PATHLEN_MAX];
		snprintf(p, PATHLEN_MAX, "%s%s%s", uopt.roots[i].path, path, HIDETAG);

		struct stat buf;
		int res = lstat(p, &buf);
		if (res == -1) continue;

		switch (buf.st_mode & S_IFMT) {
			case S_IFDIR: rmdir(p); break;
			default: unlink(p); break;
		}
	}

	return 0;
}

/**
 * dirname() in libc might not be thread-save, at least the man page states
 * "may return pointers to statically allocated memory", so we need our own
 * implementation
 */
char *u_dirname(const char *path) {
	char *ret = strdup(path);

	char *ri = rindex(ret, '/'); //this char should always be found
	*ri = '\0';

	return ret;
}

/**
 * check if path is a directory
 *
 * return 1 if it is a directory, 0 if it is a file and -1 if it does not exist
 */
int path_is_dir (const char *path)
{
	struct stat buf;
	
	if (stat (path, &buf) == -1 ) return -1;
	
	if (S_ISDIR(buf.st_mode)) return 1;
	
	return 0;
}

/**
 * Create a file that hides path below root_rw
 */
int hide_file(const char *path, int root_rw) {
	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s%s", uopt.roots[root_rw].path, path, HIDETAG);

	int res = open(p, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (res == -1) return res;

	close(res);

	return 0;
}

/**
 * Create a directory that hides path below root_rw
 */
int hide_dir(const char *path, int root_rw) {
	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s%s", uopt.roots[root_rw].path, path, HIDETAG);

	int res = mkdir(p, S_IRWXU);
	if (res == -1) return res;

	close(res);

	return 0;
}


static void initgroups_uid(uid_t uid) {
	struct passwd pwd;
	struct passwd *ppwd;
	char buf[BUFSIZ];

	if (!uopt.initgroups) return;

	getpwuid_r(uid, &pwd, buf, sizeof(buf), &ppwd);
	if (ppwd) initgroups(ppwd->pw_name, ppwd->pw_gid);
}

/**
 * Set the euid of the user performing the fs operation.
 */
void to_user(void) {
	static bool first = true;
	int errno_orig = errno;

	if (first) {
		daemon_uid = getuid();
		pthread_mutex_init(&mutex, NULL);
		first = false;
	}

	if (daemon_uid != 0) return;

	struct fuse_context *ctx = fuse_get_context();
	if (!ctx) return;

	pthread_mutex_lock(&mutex);

	initgroups_uid(ctx->uid);

	if (ctx->gid != 0)
		if (setegid(ctx->gid)) syslog(LOG_WARNING, "setegid(%i) failed\n", ctx->gid);
	if (ctx->uid != 0)
		if (seteuid(ctx->uid)) syslog(LOG_WARNING, "seteuid(%i) failed\n", ctx->uid);

	errno = errno_orig;
}

/**
 * Switch back to the root user.
 */
void to_root(void) {
	int errno_orig = errno;

	if (daemon_uid != 0) return;

        struct fuse_context *ctx = fuse_get_context();
	        if (!ctx) return;

	if (ctx->uid != 0)
		if (seteuid(0)) syslog(LOG_WARNING, "seteuid(0) failed");
	if (ctx->gid != 0)
		if (setegid(0)) syslog(LOG_WARNING, "setegid(0) failed");

	initgroups_uid(0);

	pthread_mutex_unlock(&mutex);

	errno = errno_orig;
}
